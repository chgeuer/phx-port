const MAGIC: &[u8; 4] = b"PHXP";
pub const VERSION: u8 = 1;
pub const HEADER_LENGTH: usize = 40;
pub const MAX_PACKET_LENGTH: usize = 512;
pub const MAX_SNI_LENGTH: usize = 253;

const TYPE_HELLO: u8 = 1;
const TYPE_READY: u8 = 2;
const TYPE_HANDOFF: u8 = 3;
const TYPE_ADOPTED: u8 = 4;
const TYPE_REJECTED: u8 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Handoff {
    pub connection_id: [u8; 16],
    pub peeked_length: u32,
    pub accepted_at_ns: u64,
    pub requested_sni: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Hello,
    Ready,
    Handoff(Handoff),
    Adopted {
        connection_id: [u8; 16],
    },
    Rejected {
        connection_id: [u8; 16],
        reason_code: u16,
    },
}

pub fn encode(message: &Message) -> Result<Vec<u8>, String> {
    let (message_type, connection_id, peeked_length, accepted_at_ns, reason_code, payload) =
        match message {
            Message::Hello => (TYPE_HELLO, [0; 16], 0, 0, 0, &[][..]),
            Message::Ready => (TYPE_READY, [0; 16], 0, 0, 0, &[][..]),
            Message::Handoff(handoff) => {
                let payload = handoff.requested_sni.as_bytes();
                if payload.is_empty() || payload.len() > MAX_SNI_LENGTH {
                    return Err("handoff SNI length is outside protocol bounds".to_string());
                }
                (
                    TYPE_HANDOFF,
                    handoff.connection_id,
                    handoff.peeked_length,
                    handoff.accepted_at_ns,
                    0,
                    payload,
                )
            }
            Message::Adopted { connection_id } => (TYPE_ADOPTED, *connection_id, 0, 0, 0, &[][..]),
            Message::Rejected {
                connection_id,
                reason_code,
            } => (TYPE_REJECTED, *connection_id, 0, 0, *reason_code, &[][..]),
        };

    let packet_length = HEADER_LENGTH + payload.len();
    if packet_length > MAX_PACKET_LENGTH {
        return Err("handoff packet exceeds protocol limit".to_string());
    }
    let payload_length =
        u16::try_from(payload.len()).map_err(|_| "handoff payload is too long".to_string())?;

    let mut packet = vec![0; packet_length];
    packet[0..4].copy_from_slice(MAGIC);
    packet[4] = VERSION;
    packet[5] = message_type;
    packet[6..8].copy_from_slice(&0_u16.to_be_bytes());
    packet[8..24].copy_from_slice(&connection_id);
    packet[24..28].copy_from_slice(&peeked_length.to_be_bytes());
    packet[28..36].copy_from_slice(&accepted_at_ns.to_be_bytes());
    packet[36..38].copy_from_slice(&payload_length.to_be_bytes());
    packet[38..40].copy_from_slice(&reason_code.to_be_bytes());
    packet[HEADER_LENGTH..].copy_from_slice(payload);
    Ok(packet)
}

pub fn decode(packet: &[u8]) -> Result<Message, String> {
    let frame_length = frame_length_from_header(packet)?;
    if packet.len() != frame_length {
        return Err("handoff payload length does not match packet".to_string());
    }

    let connection_id = packet[8..24]
        .try_into()
        .map_err(|_| "handoff connection ID is malformed".to_string())?;
    let peeked_length = u32::from_be_bytes(
        packet[24..28]
            .try_into()
            .map_err(|_| "handoff peek length is malformed".to_string())?,
    );
    let accepted_at_ns = u64::from_be_bytes(
        packet[28..36]
            .try_into()
            .map_err(|_| "handoff timestamp is malformed".to_string())?,
    );
    let payload_length = usize::from(u16::from_be_bytes(
        packet[36..38]
            .try_into()
            .map_err(|_| "handoff payload length is malformed".to_string())?,
    ));
    let reason_code = u16::from_be_bytes(
        packet[38..40]
            .try_into()
            .map_err(|_| "handoff reason code is malformed".to_string())?,
    );

    match packet[5] {
        TYPE_HELLO => {
            require_empty_envelope(
                payload_length,
                connection_id,
                peeked_length,
                accepted_at_ns,
                reason_code,
            )?;
            Ok(Message::Hello)
        }
        TYPE_READY => {
            require_empty_envelope(
                payload_length,
                connection_id,
                peeked_length,
                accepted_at_ns,
                reason_code,
            )?;
            Ok(Message::Ready)
        }
        TYPE_HANDOFF => {
            if payload_length == 0 || payload_length > MAX_SNI_LENGTH || reason_code != 0 {
                return Err("handoff request has invalid field values".to_string());
            }
            let requested_sni = std::str::from_utf8(&packet[HEADER_LENGTH..])
                .map_err(|_| "handoff SNI is not valid UTF-8".to_string())?
                .to_string();
            Ok(Message::Handoff(Handoff {
                connection_id,
                peeked_length,
                accepted_at_ns,
                requested_sni,
            }))
        }
        TYPE_ADOPTED => {
            require_response_envelope(payload_length, peeked_length, accepted_at_ns, reason_code)?;
            Ok(Message::Adopted { connection_id })
        }
        TYPE_REJECTED => {
            require_response_envelope(payload_length, peeked_length, accepted_at_ns, 0)?;
            if reason_code == 0 {
                return Err("handoff rejection has no reason code".to_string());
            }
            Ok(Message::Rejected {
                connection_id,
                reason_code,
            })
        }
        other => Err(format!("unknown handoff message type {other}")),
    }
}

pub fn frame_length_from_header(header: &[u8]) -> Result<usize, String> {
    if header.len() < HEADER_LENGTH {
        return Err("handoff packet is shorter than its fixed header".to_string());
    }
    if &header[0..4] != MAGIC {
        return Err("handoff packet has invalid magic".to_string());
    }
    if header[4] != VERSION {
        return Err(format!(
            "unsupported handoff protocol version {}",
            header[4]
        ));
    }
    if !matches!(
        header[5],
        TYPE_HELLO | TYPE_READY | TYPE_HANDOFF | TYPE_ADOPTED | TYPE_REJECTED
    ) {
        return Err(format!("unknown handoff message type {}", header[5]));
    }
    if header[6..8] != [0, 0] {
        return Err("handoff packet uses unsupported flags".to_string());
    }

    let payload_length = usize::from(u16::from_be_bytes([header[36], header[37]]));
    let frame_length = HEADER_LENGTH
        .checked_add(payload_length)
        .ok_or_else(|| "handoff payload length overflows frame size".to_string())?;
    if frame_length > MAX_PACKET_LENGTH {
        return Err("handoff packet exceeds protocol limit".to_string());
    }
    Ok(frame_length)
}

fn require_empty_envelope(
    payload_length: usize,
    connection_id: [u8; 16],
    peeked_length: u32,
    accepted_at_ns: u64,
    reason_code: u16,
) -> Result<(), String> {
    if payload_length != 0
        || connection_id != [0; 16]
        || peeked_length != 0
        || accepted_at_ns != 0
        || reason_code != 0
    {
        return Err("handoff handshake has unexpected field values".to_string());
    }
    Ok(())
}

fn require_response_envelope(
    payload_length: usize,
    peeked_length: u32,
    accepted_at_ns: u64,
    reason_code: u16,
) -> Result<(), String> {
    if payload_length != 0 || peeked_length != 0 || accepted_at_ns != 0 || reason_code != 0 {
        return Err("handoff response has unexpected field values".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        HEADER_LENGTH, Handoff, MAX_PACKET_LENGTH, Message, decode, encode,
        frame_length_from_header,
    };

    #[test]
    fn messages_round_trip_through_fixed_envelope() {
        let id = [0xAB; 16];
        let messages = [
            Message::Hello,
            Message::Ready,
            Message::Handoff(Handoff {
                connection_id: id,
                peeked_length: 517,
                accepted_at_ns: 42,
                requested_sni: "www.contoso.com".to_string(),
            }),
            Message::Adopted { connection_id: id },
            Message::Rejected {
                connection_id: id,
                reason_code: 7,
            },
        ];

        for message in messages {
            assert_eq!(decode(&encode(&message).unwrap()).unwrap(), message);
        }
    }

    #[test]
    fn malformed_packets_are_rejected() {
        let packet = encode(&Message::Hello).unwrap();

        assert!(decode(&packet[..39]).is_err());

        let mut bad_magic = packet.clone();
        bad_magic[0] = b'X';
        assert!(decode(&bad_magic).is_err());

        let mut bad_version = packet.clone();
        bad_version[4] = 2;
        assert!(decode(&bad_version).is_err());

        let mut bad_length = packet;
        bad_length[36..38].copy_from_slice(&1_u16.to_be_bytes());
        assert!(decode(&bad_length).is_err());
    }

    #[test]
    fn rejection_requires_a_reason() {
        let mut packet = encode(&Message::Adopted {
            connection_id: [1; 16],
        })
        .unwrap();
        packet[5] = 5;

        assert!(decode(&packet).is_err());
    }

    #[test]
    fn frame_length_is_checked_before_payload_allocation() {
        let mut header = encode(&Message::Hello).unwrap();
        header[36..38].copy_from_slice(
            &u16::try_from(MAX_PACKET_LENGTH - HEADER_LENGTH + 1)
                .unwrap()
                .to_be_bytes(),
        );

        assert!(frame_length_from_header(&header).is_err());
    }
}
