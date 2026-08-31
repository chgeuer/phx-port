using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PhxpHandoffServer;

internal sealed class HandoffReceiver(
    ServerOptions options,
    X509Certificate2 certificate,
    ILogger<HandoffReceiver> logger) : BackgroundService
{
    private const ushort RejectedDescriptor = 1;
    private const ushort RejectedDuplicate = 2;
    private const ushort RejectedAdoption = 3;
    private readonly ConcurrentDictionary<string, byte> _activeConnectionIds = new(StringComparer.Ordinal);
    private Socket? _listener;
    private int _ownsEndpoint;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("PHXP descriptor handoff is Linux-only.");
        }

        PrepareEndpoint(options.HandoffPath);
        var listener = new Socket(AddressFamily.Unix, SocketType.Seqpacket, ProtocolType.Unspecified);
        _listener = listener;

        try
        {
            listener.Bind(new UnixDomainSocketEndPoint(options.HandoffPath));
            Interlocked.Exchange(ref _ownsEndpoint, 1);
            File.SetUnixFileMode(
                options.HandoffPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
            listener.Listen(128);
            logger.LogInformation("PHXP handoff listening on {Path}", options.HandoffPath);

            while (!stoppingToken.IsCancellationRequested)
            {
                Socket control;
                try
                {
                    control = await listener.AcceptAsync(stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }

                _ = Task.Run(() => HandleControl(control, stoppingToken), CancellationToken.None);
            }
        }
        finally
        {
            listener.Dispose();
            _listener = null;
            RemoveEndpoint();
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken);
        _listener?.Dispose();
        RemoveEndpoint();
    }

    private void HandleControl(Socket control, CancellationToken stoppingToken)
    {
        using (control)
        {
            try
            {
                control.ReceiveTimeout = 2_000;
                control.SendTimeout = 2_000;
                var credentials = LinuxNative.GetPeerCredentials(checked((int)control.Handle));
                if (credentials.UserId != LinuxNative.EffectiveUserId)
                {
                    throw new InvalidDataException("PHXP peer belongs to a different user.");
                }

                var packet = new byte[PhxpProtocol.MaxPacketLength + 1];
                var helloLength = control.Receive(packet, SocketFlags.None);
                if (helloLength == 0)
                {
                    return;
                }

                PhxpProtocol.ValidateHello(packet.AsSpan(0, helloLength));
                control.Send(PhxpProtocol.CreateEmpty(PhxpProtocol.Ready, []), SocketFlags.None);

                using var descriptor = LinuxNative.ReceiveFileDescriptor(
                    checked((int)control.Handle),
                    packet,
                    out var packetLength);
                var request = PhxpProtocol.ParseHandoff(packet.AsSpan(0, packetLength));

                var connectionKey = Convert.ToHexString(request.ConnectionId);
                if (!_activeConnectionIds.TryAdd(connectionKey, 0))
                {
                    TryReject(control, request.ConnectionId, RejectedDuplicate);
                    throw new InvalidDataException("Duplicate PHXP connection identifier.");
                }

                try
                {
                    LinuxNative.ValidateConnectedStream(descriptor.Value);
                }
                catch
                {
                    _activeConnectionIds.TryRemove(connectionKey, out _);
                    TryReject(control, request.ConnectionId, RejectedDescriptor);
                    throw;
                }

                Socket client;
                var handle = new SafeSocketHandle((nint)descriptor.Release(), ownsHandle: true);
                try
                {
                    client = new Socket(handle);
                    _ = client.RemoteEndPoint
                        ?? throw new InvalidDataException("Handed-off stream socket is not connected.");
                }
                catch
                {
                    handle.Dispose();
                    _activeConnectionIds.TryRemove(connectionKey, out _);
                    TryReject(control, request.ConnectionId, RejectedAdoption);
                    throw;
                }

                try
                {
                    control.Send(
                        PhxpProtocol.CreateEmpty(PhxpProtocol.Adopted, request.ConnectionId),
                        SocketFlags.None);
                }
                catch
                {
                    client.Dispose();
                    _activeConnectionIds.TryRemove(connectionKey, out _);
                    throw;
                }

                _ = ServeTlsAsync(client, request, connectionKey, stoppingToken);
            }
            catch (SocketException exception)
            {
                logger.LogDebug(exception, "PHXP control connection ended.");
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Rejected PHXP handoff.");
            }
        }
    }

    private async Task ServeTlsAsync(
        Socket client,
        HandoffRequest request,
        string connectionKey,
        CancellationToken stoppingToken)
    {
        var peer = client.RemoteEndPoint;
        var local = client.LocalEndPoint;

        try
        {
            await using var network = new NetworkStream(client, ownsSocket: true);
            await using var tls = new SslStream(network, leaveInnerStreamOpen: false);
            await tls.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ApplicationProtocols = [SslApplicationProtocol.Http11]
                },
                stoppingToken);

            var requestBytes = await ReadHttpHeadersAsync(tls, stoppingToken);
            var body = Encoding.UTF8.GetBytes(
                $"phxp .NET 10 handoff example\n"
                + "listener=phxp-handoff-https\n"
                + $"peer={Format(peer)}\n"
                + $"local={Format(local)}\n"
                + $"sni={request.RequestedSni}\n"
                + $"peeked_bytes={request.PeekedLength}\n");
            var header = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + $"Content-Length: {body.Length}\r\n"
                + "Connection: close\r\n"
                + "\r\n");
            await tls.WriteAsync(header, stoppingToken);
            await tls.WriteAsync(body, stoppingToken);
            await tls.FlushAsync(stoppingToken);

            logger.LogInformation(
                "Served handed-off TLS connection {ConnectionId} from {Peer} for {Sni} ({RequestBytes} request bytes)",
                connectionKey,
                peer,
                request.RequestedSni,
                requestBytes);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Handed-off TLS connection {ConnectionId} from {Peer} failed",
                connectionKey,
                peer);
            client.Dispose();
        }
        finally
        {
            _activeConnectionIds.TryRemove(connectionKey, out _);
        }
    }

    private static async Task<int> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        const int maximumLength = 16 * 1024;
        var buffer = new byte[1024];
        var total = 0;
        var matched = 0;
        var terminator = new byte[] { 13, 10, 13, 10 };

        while (total < maximumLength)
        {
            var count = await stream.ReadAsync(
                buffer.AsMemory(0, Math.Min(buffer.Length, maximumLength - total)),
                cancellationToken);
            if (count == 0)
            {
                throw new EndOfStreamException("TLS client closed before sending HTTP headers.");
            }

            total += count;
            for (var index = 0; index < count; index++)
            {
                matched = buffer[index] == terminator[matched] ? matched + 1 : buffer[index] == terminator[0] ? 1 : 0;
                if (matched == terminator.Length)
                {
                    return total;
                }
            }
        }

        throw new InvalidDataException("HTTP request headers exceed 16 KiB.");
    }

    private static string Format(EndPoint? endpoint) => endpoint?.ToString() ?? "unknown";

    private static void TryReject(Socket control, ReadOnlySpan<byte> connectionId, ushort reason)
    {
        try
        {
            control.Send(PhxpProtocol.CreateEmpty(PhxpProtocol.Rejected, connectionId, reason));
        }
        catch
        {
        }
    }

    private static void PrepareEndpoint(string path)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException();
        }

        var parent = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException("PHXP endpoint path has no parent directory.");
        Directory.CreateDirectory(parent);
        File.SetUnixFileMode(
            parent,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        if (!File.Exists(path))
        {
            return;
        }

        using var probe = new Socket(AddressFamily.Unix, SocketType.Seqpacket, ProtocolType.Unspecified);
        try
        {
            probe.Connect(new UnixDomainSocketEndPoint(path));
            throw new InvalidOperationException($"Another PHXP receiver is already listening at {path}.");
        }
        catch (SocketException)
        {
            File.Delete(path);
        }
    }

    private void RemoveEndpoint()
    {
        if (Interlocked.Exchange(ref _ownsEndpoint, 0) == 0)
        {
            return;
        }

        try
        {
            File.Delete(options.HandoffPath);
        }
        catch (FileNotFoundException)
        {
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Could not remove PHXP endpoint {Path}", options.HandoffPath);
        }
    }
}
