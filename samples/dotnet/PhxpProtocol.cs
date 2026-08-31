using System.Buffers.Binary;
using System.Text;

namespace PhxpHandoffServer;

internal static class PhxpProtocol
{
    public const int HeaderLength = 40;
    public const int MaxPacketLength = 512;
    public const byte Hello = 1;
    public const byte Ready = 2;
    public const byte Handoff = 3;
    public const byte Adopted = 4;
    public const byte Rejected = 5;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static ReadOnlySpan<byte> Magic => "PHXP"u8;

    public static void ValidateHello(ReadOnlySpan<byte> packet)
    {
        ValidateHeader(packet, Hello);
        if (packet.Length != HeaderLength || packet[6..].ContainsAnyExcept((byte)0))
        {
            throw new InvalidDataException("Invalid PHXP HELLO envelope.");
        }
    }

    public static HandoffRequest ParseHandoff(ReadOnlySpan<byte> packet)
    {
        ValidateHeader(packet, Handoff);

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(packet[36..38]);
        if (payloadLength is 0 or > 253
            || packet.Length != HeaderLength + payloadLength
            || BinaryPrimitives.ReadUInt16BigEndian(packet[38..40]) != 0)
        {
            throw new InvalidDataException("Invalid PHXP HANDOFF fields.");
        }

        var id = packet[8..24].ToArray();
        var peekedLength = BinaryPrimitives.ReadUInt32BigEndian(packet[24..28]);
        var acceptedAtNanoseconds = BinaryPrimitives.ReadUInt64BigEndian(packet[28..36]);
        var sni = StrictUtf8.GetString(packet[HeaderLength..]);
        return new HandoffRequest(id, peekedLength, acceptedAtNanoseconds, sni);
    }

    public static byte[] CreateEmpty(byte messageType, ReadOnlySpan<byte> connectionId, ushort reasonCode = 0)
    {
        if (messageType is not (Hello or Ready or Adopted or Rejected))
        {
            throw new ArgumentOutOfRangeException(nameof(messageType));
        }

        if (messageType is Hello or Ready && (!connectionId.IsEmpty || reasonCode != 0))
        {
            throw new ArgumentException("HELLO and READY must have empty envelopes.");
        }

        if (messageType is Adopted or Rejected && connectionId.Length != 16)
        {
            throw new ArgumentException("Responses must include a 16-byte connection ID.");
        }

        if ((messageType == Rejected) != (reasonCode != 0))
        {
            throw new ArgumentException("Only REJECTED has a nonzero reason code.");
        }

        var packet = new byte[HeaderLength];
        Magic.CopyTo(packet);
        packet[4] = 1;
        packet[5] = messageType;
        connectionId.CopyTo(packet.AsSpan(8, connectionId.Length));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(38, 2), reasonCode);
        return packet;
    }

    private static void ValidateHeader(ReadOnlySpan<byte> packet, byte expectedType)
    {
        if (packet.Length is < HeaderLength or > MaxPacketLength)
        {
            throw new InvalidDataException("PHXP packet length is invalid.");
        }

        if (!packet[..4].SequenceEqual(Magic)
            || packet[4] != 1
            || packet[5] != expectedType)
        {
            throw new InvalidDataException("PHXP packet header is invalid.");
        }

        if (packet[6] != 0 || packet[7] != 0)
        {
            throw new InvalidDataException("PHXP version 1 flags must be zero.");
        }
    }
}

internal sealed record HandoffRequest(
    byte[] ConnectionId,
    uint PeekedLength,
    ulong AcceptedAtNanoseconds,
    string RequestedSni);
