using System.ComponentModel;
using System.Runtime.InteropServices;

namespace PhxpHandoffServer;

internal static unsafe class LinuxNative
{
    private const int SolSocket = 1;
    private const int ScmRights = 1;
    private const int SoType = 3;
    private const int SoPeerCred = 17;
    private const int SockStream = 1;
    private const int MsgCtrunc = 0x08;
    private const int MsgTrunc = 0x20;
    private const int MsgCmsgCloexec = 0x40000000;
    private const int Eintr = 4;
    private const int ControlBufferLength = 64;
    private static readonly nuint ControlHeaderLength = Align((nuint)sizeof(ControlMessageHeader));

    public static uint EffectiveUserId => geteuid();

    public static PeerCredentials GetPeerCredentials(int socket)
    {
        var length = (uint)sizeof(PeerCredentials);
        if (getsockopt(socket, SolSocket, SoPeerCred, out PeerCredentials credentials, ref length) != 0
            || length != sizeof(PeerCredentials))
        {
            throw Error("getsockopt(SO_PEERCRED)");
        }

        return credentials;
    }

    public static void ValidateConnectedStream(int socket)
    {
        var length = (uint)sizeof(int);
        if (getsockopt(socket, SolSocket, SoType, out int socketType, ref length) != 0)
        {
            throw Error("getsockopt(SO_TYPE)");
        }

        if (socketType != SockStream)
        {
            throw new InvalidDataException("Handed-off descriptor is not a stream socket.");
        }
    }

    public static ReceivedFileDescriptor ReceiveFileDescriptor(int socket, byte[] packet, out int packetLength)
    {
        Span<byte> controlBuffer = stackalloc byte[ControlBufferLength];
        controlBuffer.Clear();

        fixed (byte* packetPointer = packet)
        fixed (byte* controlPointer = controlBuffer)
        {
            var vector = new IoVector
            {
                Base = packetPointer,
                Length = (nuint)packet.Length
            };
            var message = new MessageHeader
            {
                IoVector = &vector,
                IoVectorLength = 1,
                Control = controlPointer,
                ControlLength = (nuint)controlBuffer.Length
            };

            nint received;
            do
            {
                received = recvmsg(socket, &message, MsgCmsgCloexec);
            } while (received < 0 && Marshal.GetLastPInvokeError() == Eintr);

            if (received < 0)
            {
                throw Error("recvmsg");
            }

            if (received == 0)
            {
                throw new EndOfStreamException("PHXP control connection closed before HANDOFF.");
            }

            if ((message.Flags & (MsgTrunc | MsgCtrunc)) != 0 || received > PhxpProtocol.MaxPacketLength)
            {
                CloseReceivedDescriptors(controlPointer, message.ControlLength);
                throw new InvalidDataException("PHXP packet or ancillary data was truncated.");
            }

            var descriptors = ReadDescriptors(controlPointer, message.ControlLength);
            if (descriptors.Count != 1)
            {
                foreach (var descriptor in descriptors)
                {
                    close(descriptor);
                }

                throw new InvalidDataException("PHXP HANDOFF must contain exactly one descriptor.");
            }

            packetLength = checked((int)received);
            return new ReceivedFileDescriptor(descriptors[0]);
        }
    }

    public static void Close(int descriptor)
    {
        if (descriptor >= 0)
        {
            close(descriptor);
        }
    }

    private static List<int> ReadDescriptors(byte* control, nuint controlLength)
    {
        var descriptors = new List<int>();
        nuint offset = 0;

        while (offset + ControlHeaderLength <= controlLength)
        {
            var header = (ControlMessageHeader*)(control + offset);
            if (header->Length < ControlHeaderLength || offset + header->Length > controlLength)
            {
                foreach (var descriptor in descriptors)
                {
                    close(descriptor);
                }

                throw new InvalidDataException("Malformed SCM_RIGHTS control message.");
            }

            if (header->Level == SolSocket && header->Type == ScmRights)
            {
                var dataLength = header->Length - ControlHeaderLength;
                if (dataLength % sizeof(int) != 0)
                {
                    foreach (var descriptor in descriptors)
                    {
                        close(descriptor);
                    }

                    throw new InvalidDataException("Malformed SCM_RIGHTS descriptor array.");
                }

                var data = (int*)(control + offset + ControlHeaderLength);
                for (nuint index = 0; index < dataLength / sizeof(int); index++)
                {
                    descriptors.Add(data[index]);
                }
            }

            offset += Align(header->Length);
        }

        return descriptors;
    }

    private static void CloseReceivedDescriptors(byte* control, nuint controlLength)
    {
        try
        {
            foreach (var descriptor in ReadDescriptors(control, controlLength))
            {
                close(descriptor);
            }
        }
        catch (InvalidDataException)
        {
        }
    }

    private static nuint Align(nuint length)
    {
        var alignment = (nuint)sizeof(nuint);
        return (length + alignment - 1) & ~(alignment - 1);
    }

    private static Win32Exception Error(string operation) =>
        new(Marshal.GetLastPInvokeError(), operation);

    [StructLayout(LayoutKind.Sequential)]
    private struct IoVector
    {
        public void* Base;
        public nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MessageHeader
    {
        public void* Name;
        public uint NameLength;
        public IoVector* IoVector;
        public nuint IoVectorLength;
        public void* Control;
        public nuint ControlLength;
        public int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ControlMessageHeader
    {
        public nuint Length;
        public int Level;
        public int Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct PeerCredentials
    {
        public readonly int ProcessId;
        public readonly uint UserId;
        public readonly uint GroupId;
    }

    [DllImport("libc", SetLastError = true)]
    private static extern nint recvmsg(int socket, MessageHeader* message, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(
        int socket,
        int level,
        int option,
        out PeerCredentials value,
        ref uint length);

    [DllImport("libc", SetLastError = true)]
    private static extern int getsockopt(
        int socket,
        int level,
        int option,
        out int value,
        ref uint length);

    [DllImport("libc")]
    private static extern uint geteuid();

    [DllImport("libc")]
    private static extern int close(int descriptor);
}

internal sealed class ReceivedFileDescriptor(int value) : IDisposable
{
    private int _value = value;

    public int Value => _value >= 0
        ? _value
        : throw new ObjectDisposedException(nameof(ReceivedFileDescriptor));

    public int Release()
    {
        var value = _value;
        if (value < 0)
        {
            throw new ObjectDisposedException(nameof(ReceivedFileDescriptor));
        }

        _value = -1;
        return value;
    }

    public void Dispose()
    {
        var value = Interlocked.Exchange(ref _value, -1);
        LinuxNative.Close(value);
    }
}
