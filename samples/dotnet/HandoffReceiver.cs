using System.Collections.Concurrent;
using System.Net.Sockets;
using Microsoft.Win32.SafeHandles;

namespace PhxpHandoffServer;

internal sealed class HandoffReceiver(
    ServerOptions options,
    HandoffTransportFactory transport,
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
                catch (SocketException exception)
                {
                    logger.LogWarning(exception, "PHXP accept failed; retrying.");
                    await Task.Delay(100, stoppingToken);
                    continue;
                }

                _ = Task.Run(() => HandleControl(control), CancellationToken.None);
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

    private void HandleControl(Socket control)
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
                    client.Blocking = true;
                    _ = client.RemoteEndPoint
                        ?? throw new InvalidDataException("Handed-off stream socket is not connected.");
                    if (client.AddressFamily is not AddressFamily.InterNetwork
                        and not AddressFamily.InterNetworkV6)
                    {
                        throw new InvalidDataException("Handed-off descriptor is not a TCP socket.");
                    }
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
                    transport.Enqueue(
                        client,
                        new HandoffConnectionFeature(
                            request.RequestedSni,
                            request.PeekedLength,
                            request.AcceptedAtNanoseconds),
                        () => _activeConnectionIds.TryRemove(connectionKey, out _));
                }
                catch
                {
                    client.Dispose();
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
                catch (SocketException exception)
                {
                    logger.LogDebug(
                        exception,
                        "PHXP connection {ConnectionId} was adopted, but its acknowledgement was lost.",
                        connectionKey);
                }
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
        if (!LinuxNative.IsSocket(path))
        {
            throw new InvalidOperationException($"Refusing to replace non-socket handoff path {path}.");
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
