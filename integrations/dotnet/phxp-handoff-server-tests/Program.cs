using System.Buffers.Binary;
using System.Text;
using PhxpHandoffServer;

var tests = new (string Name, Action Run)[]
{
    ("HELLO codec", HelloCodec),
    ("HANDOFF codec", HandoffCodec),
    ("malformed packets", MalformedPackets),
    ("endpoint derivation", EndpointDerivation)
};

foreach (var (name, run) in tests)
{
    run();
    Console.WriteLine($"PASS {name}");
}

return;

static void HelloCodec()
{
    var packet = PhxpProtocol.CreateEmpty(PhxpProtocol.Hello, []);
    PhxpProtocol.ValidateHello(packet);
    Equal(PhxpProtocol.HeaderLength, packet.Length);
    Equal((byte)1, packet[4]);
    Equal(PhxpProtocol.Hello, packet[5]);
}

static void HandoffCodec()
{
    var id = Enumerable.Range(0, 16).Select(value => (byte)value).ToArray();
    var packet = CreateHandoff(id, 517, 42, "www.contoso.com");
    var handoff = PhxpProtocol.ParseHandoff(packet);

    SequenceEqual(id, handoff.ConnectionId);
    Equal(517u, handoff.PeekedLength);
    Equal(42ul, handoff.AcceptedAtNanoseconds);
    Equal("www.contoso.com", handoff.RequestedSni);

    var adopted = PhxpProtocol.CreateEmpty(PhxpProtocol.Adopted, id);
    Equal(PhxpProtocol.Adopted, adopted[5]);
    SequenceEqual(id, adopted.AsSpan(8, 16));
}

static void MalformedPackets()
{
    var hello = PhxpProtocol.CreateEmpty(PhxpProtocol.Hello, []);
    Throws<InvalidDataException>(() => PhxpProtocol.ValidateHello(hello[..39]));

    var badMagic = hello.ToArray();
    badMagic[0] = (byte)'X';
    Throws<InvalidDataException>(() => PhxpProtocol.ValidateHello(badMagic));

    var badFlags = hello.ToArray();
    badFlags[7] = 1;
    Throws<InvalidDataException>(() => PhxpProtocol.ValidateHello(badFlags));

    var badLength = CreateHandoff(new byte[16], 0, 0, "example.test");
    BinaryPrimitives.WriteUInt16BigEndian(badLength.AsSpan(36, 2), 1);
    Throws<InvalidDataException>(() => PhxpProtocol.ParseHandoff(badLength));
}

static void EndpointDerivation()
{
    const string runtime = "/run/user/1000";
    const string expectedHash = "f1e7030384e99db9bf19a666cf6fbecc7951b6eade2e0d09f889e9263b1dd9d3";
    var previous = Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR");

    try
    {
        Environment.SetEnvironmentVariable("XDG_RUNTIME_DIR", runtime);
        Equal(
            $"{runtime}/phx-port/handoff/{expectedHash}.sock",
            ServerOptions.DeriveHandoffPath("/srv/contoso", "https"));
    }
    finally
    {
        Environment.SetEnvironmentVariable("XDG_RUNTIME_DIR", previous);
    }
}

static byte[] CreateHandoff(
    ReadOnlySpan<byte> connectionId,
    uint peekedLength,
    ulong acceptedAtNanoseconds,
    string sni)
{
    var payload = Encoding.UTF8.GetBytes(sni);
    var packet = new byte[PhxpProtocol.HeaderLength + payload.Length];
    "PHXP"u8.CopyTo(packet);
    packet[4] = 1;
    packet[5] = PhxpProtocol.Handoff;
    connectionId.CopyTo(packet.AsSpan(8, 16));
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24, 4), peekedLength);
    BinaryPrimitives.WriteUInt64BigEndian(packet.AsSpan(28, 8), acceptedAtNanoseconds);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(36, 2), checked((ushort)payload.Length));
    payload.CopyTo(packet, PhxpProtocol.HeaderLength);
    return packet;
}

static void Equal<T>(T expected, T actual)
    where T : IEquatable<T>
{
    if (!expected.Equals(actual))
    {
        throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }
}

static void SequenceEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
{
    if (!expected.SequenceEqual(actual))
    {
        throw new InvalidOperationException("Byte sequences differ.");
    }
}

static void Throws<TException>(Action action)
    where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
}
