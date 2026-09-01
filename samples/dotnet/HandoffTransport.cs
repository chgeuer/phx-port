using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

namespace PhxpHandoffServer;

internal sealed class HandoffEndPoint(string path) : EndPoint
{
    public string Path { get; } = path;

    public override string ToString() => $"phxp://{Path}";
}

internal sealed record HandoffConnectionFeature(
    string RequestedSni,
    uint PeekedLength,
    ulong AcceptedAtNanoseconds);

internal sealed class HandoffTransportFactory :
    IConnectionListenerFactory,
    IConnectionListenerFactorySelector
{
    private const int PendingConnectionLimit = 128;
    private HandoffConnectionListener? _listener;

    public bool CanBind(EndPoint endpoint) => endpoint is HandoffEndPoint;

    public ValueTask<IConnectionListener> BindAsync(
        EndPoint endpoint,
        CancellationToken cancellationToken = default)
    {
        var listener = new HandoffConnectionListener(
            endpoint,
            PendingConnectionLimit,
            bound => Interlocked.CompareExchange(ref _listener, null, bound));
        if (Interlocked.CompareExchange(ref _listener, listener, null) is not null)
        {
            throw new InvalidOperationException("The PHXP Kestrel transport is already bound.");
        }

        return ValueTask.FromResult<IConnectionListener>(listener);
    }

    public void Enqueue(
        Socket socket,
        HandoffConnectionFeature feature,
        Action release)
    {
        var listener = Volatile.Read(ref _listener)
            ?? throw new InvalidOperationException("The PHXP Kestrel transport is not bound.");
        listener.Enqueue(socket, feature, release);
    }
}

internal sealed class HandoffConnectionListener(
    EndPoint endpoint,
    int capacity,
    Action<HandoffConnectionListener> release) : IConnectionListener
{
    private readonly Channel<AdoptedSocket> _connections =
        Channel.CreateBounded<AdoptedSocket>(
            new BoundedChannelOptions(capacity)
            {
                SingleReader = true,
                FullMode = BoundedChannelFullMode.Wait
            });
    private int _disposed;

    public EndPoint EndPoint { get; } = endpoint;

    public void Enqueue(
        Socket socket,
        HandoffConnectionFeature feature,
        Action release)
    {
        var adopted = new AdoptedSocket(socket, feature, release);
        if (!_connections.Writer.TryWrite(adopted))
        {
            adopted.Close();
            throw new InvalidOperationException("The PHXP Kestrel transport is stopping.");
        }
    }

    public async ValueTask<ConnectionContext?> AcceptAsync(
        CancellationToken cancellationToken = default)
    {
        while (await _connections.Reader.WaitToReadAsync(cancellationToken))
        {
            if (_connections.Reader.TryRead(out var adopted))
            {
                return new HandoffConnectionContext(adopted);
            }
        }

        return null;
    }

    public ValueTask UnbindAsync(CancellationToken cancellationToken = default)
    {
        _connections.Writer.TryComplete();
        Drain();
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return ValueTask.CompletedTask;
        }

        _connections.Writer.TryComplete();
        Drain();
        release(this);
        return ValueTask.CompletedTask;
    }

    private void Drain()
    {
        while (_connections.Reader.TryRead(out var adopted))
        {
            adopted.Close();
        }
    }
}

internal sealed class AdoptedSocket(
    Socket socket,
    HandoffConnectionFeature feature,
    Action release)
{
    private Action? _release = release;

    public Socket Socket { get; } = socket;
    public HandoffConnectionFeature Feature { get; } = feature;

    public void Close()
    {
        if (Interlocked.Exchange(ref _release, null) is { } callback)
        {
            Socket.Dispose();
            callback();
        }
    }

    public void Release() => Interlocked.Exchange(ref _release, null)?.Invoke();
}

internal sealed class HandoffConnectionContext :
    ConnectionContext,
    IConnectionSocketFeature
{
    private readonly AdoptedSocket _handoff;
    private readonly NetworkStream _stream;
    private readonly PipeReader _input;
    private readonly PipeWriter _output;
    private readonly CancellationTokenSource _closed = new();
    private ConnectionAbortedException? _abortReason;
    private int _disposed;

    public HandoffConnectionContext(AdoptedSocket handoff)
    {
        _handoff = handoff;
        _stream = new NetworkStream(handoff.Socket, ownsSocket: true);
        _input = PipeReader.Create(
            _stream,
            new StreamPipeReaderOptions(leaveOpen: true));
        _output = PipeWriter.Create(
            _stream,
            new StreamPipeWriterOptions(leaveOpen: true));

        ConnectionId = Guid.NewGuid().ToString("N");
        LocalEndPoint = handoff.Socket.LocalEndPoint;
        RemoteEndPoint = handoff.Socket.RemoteEndPoint;
        Transport = new DuplexPipe(_input, _output);
        Features = new FeatureCollection();
        Features.Set<IConnectionSocketFeature>(this);
        Features.Set(handoff.Feature);
    }

    public override string ConnectionId { get; set; }
    public override IFeatureCollection Features { get; }
    public override IDictionary<object, object?> Items { get; set; } =
        new Dictionary<object, object?>();
    public override IDuplexPipe Transport { get; set; }
    public override CancellationToken ConnectionClosed
    {
        get => _closed.Token;
        set { }
    }

    Socket IConnectionSocketFeature.Socket => _handoff.Socket;

    public override void Abort(ConnectionAbortedException abortReason)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        _abortReason = abortReason;
        _closed.Cancel();
        _input.CancelPendingRead();
        try
        {
            _handoff.Socket.Shutdown(SocketShutdown.Both);
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _closed.Cancel();
        _input.Complete(_abortReason);
        _output.Complete(_abortReason);
        await _stream.DisposeAsync();
        _handoff.Release();
    }

    private sealed class DuplexPipe(PipeReader input, PipeWriter output) : IDuplexPipe
    {
        public PipeReader Input { get; } = input;
        public PipeWriter Output { get; } = output;
    }
}
