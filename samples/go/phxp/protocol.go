package phxp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	Version         = 1
	HeaderLength    = 40
	MaxPacketLength = 512
	MaxSNILength    = 253
)

type MessageType uint8

const (
	TypeHello    MessageType = 1
	TypeReady    MessageType = 2
	TypeHandoff  MessageType = 3
	TypeAdopted  MessageType = 4
	TypeRejected MessageType = 5
)

type Message struct {
	Type          MessageType
	ConnectionID  [16]byte
	PeekedLength  uint32
	AcceptedAtNS  uint64
	RequestedSNI  string
	RejectionCode uint16
}

func Encode(message Message) ([]byte, error) {
	var payload []byte
	switch message.Type {
	case TypeHello, TypeReady:
		if message.ConnectionID != ([16]byte{}) || message.PeekedLength != 0 ||
			message.AcceptedAtNS != 0 || message.RequestedSNI != "" ||
			message.RejectionCode != 0 {
			return nil, errors.New("PHXP handshake has unexpected field values")
		}
	case TypeHandoff:
		payload = []byte(message.RequestedSNI)
		if len(payload) == 0 || len(payload) > MaxSNILength {
			return nil, errors.New("PHXP handoff SNI length is outside protocol bounds")
		}
		if !utf8.Valid(payload) {
			return nil, errors.New("PHXP handoff SNI is not valid UTF-8")
		}
		if message.RejectionCode != 0 {
			return nil, errors.New("PHXP handoff request has a rejection code")
		}
	case TypeAdopted:
		if message.PeekedLength != 0 || message.AcceptedAtNS != 0 ||
			message.RequestedSNI != "" || message.RejectionCode != 0 {
			return nil, errors.New("PHXP adopted response has unexpected field values")
		}
	case TypeRejected:
		if message.PeekedLength != 0 || message.AcceptedAtNS != 0 ||
			message.RequestedSNI != "" || message.RejectionCode == 0 {
			return nil, errors.New("PHXP rejected response has unexpected field values")
		}
	default:
		return nil, fmt.Errorf("unknown PHXP message type %d", message.Type)
	}

	packetLength := HeaderLength + len(payload)
	if packetLength > MaxPacketLength {
		return nil, errors.New("PHXP packet exceeds protocol limit")
	}
	packet := make([]byte, packetLength)
	copy(packet[0:4], "PHXP")
	packet[4] = Version
	packet[5] = byte(message.Type)
	copy(packet[8:24], message.ConnectionID[:])
	binary.BigEndian.PutUint32(packet[24:28], message.PeekedLength)
	binary.BigEndian.PutUint64(packet[28:36], message.AcceptedAtNS)
	binary.BigEndian.PutUint16(packet[36:38], uint16(len(payload)))
	binary.BigEndian.PutUint16(packet[38:40], message.RejectionCode)
	copy(packet[HeaderLength:], payload)
	return packet, nil
}

func Decode(packet []byte) (Message, error) {
	frameLength, err := FrameLength(packet)
	if err != nil {
		return Message{}, err
	}
	if len(packet) != frameLength {
		return Message{}, errors.New("PHXP payload length does not match packet")
	}

	var message Message
	message.Type = MessageType(packet[5])
	copy(message.ConnectionID[:], packet[8:24])
	message.PeekedLength = binary.BigEndian.Uint32(packet[24:28])
	message.AcceptedAtNS = binary.BigEndian.Uint64(packet[28:36])
	payloadLength := int(binary.BigEndian.Uint16(packet[36:38]))
	message.RejectionCode = binary.BigEndian.Uint16(packet[38:40])

	switch message.Type {
	case TypeHello, TypeReady:
		if payloadLength != 0 || message.ConnectionID != ([16]byte{}) ||
			message.PeekedLength != 0 || message.AcceptedAtNS != 0 ||
			message.RejectionCode != 0 {
			return Message{}, errors.New("PHXP handshake has unexpected field values")
		}
	case TypeHandoff:
		if payloadLength == 0 || payloadLength > MaxSNILength || message.RejectionCode != 0 {
			return Message{}, errors.New("PHXP handoff request has invalid field values")
		}
		payload := packet[HeaderLength:]
		if !utf8.Valid(payload) {
			return Message{}, errors.New("PHXP handoff SNI is not valid UTF-8")
		}
		message.RequestedSNI = string(payload)
	case TypeAdopted:
		if payloadLength != 0 || message.PeekedLength != 0 ||
			message.AcceptedAtNS != 0 || message.RejectionCode != 0 {
			return Message{}, errors.New("PHXP response has unexpected field values")
		}
	case TypeRejected:
		if payloadLength != 0 || message.PeekedLength != 0 ||
			message.AcceptedAtNS != 0 || message.RejectionCode == 0 {
			return Message{}, errors.New("PHXP rejection has invalid field values")
		}
	default:
		return Message{}, fmt.Errorf("unknown PHXP message type %d", message.Type)
	}
	return message, nil
}

func FrameLength(header []byte) (int, error) {
	if len(header) < HeaderLength {
		return 0, errors.New("PHXP packet is shorter than its fixed header")
	}
	if !bytes.Equal(header[0:4], []byte("PHXP")) {
		return 0, errors.New("PHXP packet has invalid magic")
	}
	if header[4] != Version {
		return 0, fmt.Errorf("unsupported PHXP protocol version %d", header[4])
	}
	switch MessageType(header[5]) {
	case TypeHello, TypeReady, TypeHandoff, TypeAdopted, TypeRejected:
	default:
		return 0, fmt.Errorf("unknown PHXP message type %d", header[5])
	}
	if header[6] != 0 || header[7] != 0 {
		return 0, errors.New("PHXP packet uses unsupported flags")
	}
	length := HeaderLength + int(binary.BigEndian.Uint16(header[36:38]))
	if length > MaxPacketLength {
		return 0, errors.New("PHXP packet exceeds protocol limit")
	}
	return length, nil
}

func readStreamFrame(reader io.Reader, initial []byte) ([]byte, error) {
	frame := append([]byte(nil), initial...)
	if len(frame) > MaxPacketLength {
		return nil, errors.New("PHXP stream contains bytes beyond the maximum frame")
	}
	if len(frame) < HeaderLength {
		missing := HeaderLength - len(frame)
		frame = append(frame, make([]byte, missing)...)
		if _, err := io.ReadFull(reader, frame[len(frame)-missing:]); err != nil {
			return nil, fmt.Errorf("unexpected EOF in PHXP frame header: %w", err)
		}
	}
	length, err := FrameLength(frame[:HeaderLength])
	if err != nil {
		return nil, err
	}
	if len(frame) > length {
		return nil, errors.New("PHXP stream contains bytes beyond the declared frame")
	}
	if len(frame) < length {
		missing := length - len(frame)
		frame = append(frame, make([]byte, missing)...)
		if _, err := io.ReadFull(reader, frame[len(frame)-missing:]); err != nil {
			return nil, fmt.Errorf("unexpected EOF in PHXP frame payload: %w", err)
		}
	}
	return frame, nil
}
