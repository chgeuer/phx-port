package phxp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestProtocolRoundTrip(t *testing.T) {
	id := [16]byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab}
	messages := []Message{
		{Type: TypeHello},
		{Type: TypeReady},
		{
			Type:         TypeHandoff,
			ConnectionID: id,
			PeekedLength: 517,
			AcceptedAtNS: 42,
			RequestedSNI: "www.contoso.com",
		},
		{Type: TypeAdopted, ConnectionID: id},
		{Type: TypeRejected, ConnectionID: id, RejectionCode: 7},
	}
	for _, message := range messages {
		packet, err := Encode(message)
		if err != nil {
			t.Fatalf("Encode(%v): %v", message.Type, err)
		}
		decoded, err := Decode(packet)
		if err != nil {
			t.Fatalf("Decode(%v): %v", message.Type, err)
		}
		if decoded != message {
			t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", decoded, message)
		}
	}
}

func TestProtocolRejectsMalformedEnvelopes(t *testing.T) {
	hello := mustEncode(Message{Type: TypeHello})
	cases := [][]byte{
		hello[:HeaderLength-1],
		append([]byte("X"), hello[1:]...),
		func() []byte {
			packet := append([]byte(nil), hello...)
			packet[4] = 2
			return packet
		}(),
		func() []byte {
			packet := append([]byte(nil), hello...)
			packet[6] = 1
			return packet
		}(),
		func() []byte {
			packet := append([]byte(nil), hello...)
			binary.BigEndian.PutUint16(packet[36:38], MaxPacketLength-HeaderLength+1)
			return packet
		}(),
		func() []byte {
			packet := append([]byte(nil), hello...)
			packet[8] = 1
			return packet
		}(),
	}
	for index, packet := range cases {
		if _, err := Decode(packet); err == nil {
			t.Fatalf("malformed case %d was accepted", index)
		}
	}
}

func TestStreamFramingIsBoundedAndExact(t *testing.T) {
	packet := mustEncode(Message{
		Type:         TypeHandoff,
		ConnectionID: [16]byte{1},
		RequestedSNI: "example.test",
		PeekedLength: 123,
		AcceptedAtNS: 456,
	})
	for boundary := 1; boundary < len(packet); boundary++ {
		frame, err := readStreamFrame(bytes.NewReader(packet[boundary:]), packet[:boundary])
		if err != nil {
			t.Fatalf("split %d: %v", boundary, err)
		}
		if !bytes.Equal(frame, packet) {
			t.Fatalf("split %d changed frame", boundary)
		}
	}

	coalesced := append(append([]byte(nil), mustEncode(Message{Type: TypeHello})...), mustEncode(Message{Type: TypeReady})...)
	if _, err := readStreamFrame(bytes.NewReader(nil), coalesced); err == nil {
		t.Fatal("coalesced frames were accepted")
	}
}
