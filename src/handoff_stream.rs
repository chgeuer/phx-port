use crate::handoff_protocol::{self, HEADER_LENGTH, MAX_PACKET_LENGTH};
use std::io::{self, Read};

pub(crate) fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut initial = vec![0_u8; MAX_PACKET_LENGTH + 1];
    let received = reader
        .read(&mut initial)
        .map_err(|error| format!("cannot read PHXP frame: {error}"))?;
    if received == 0 {
        return Err("unexpected EOF before PHXP frame header".to_string());
    }
    initial.truncate(received);
    complete_frame(reader, initial)
}

pub(crate) fn complete_frame(
    reader: &mut impl Read,
    mut frame: Vec<u8>,
) -> Result<Vec<u8>, String> {
    if frame.len() > MAX_PACKET_LENGTH {
        return Err("PHXP stream contains bytes beyond the maximum frame".to_string());
    }
    if frame.len() < HEADER_LENGTH {
        read_exact_part(
            reader,
            &mut frame,
            HEADER_LENGTH,
            "unexpected EOF in PHXP frame header",
        )?;
    }

    let frame_length = handoff_protocol::frame_length_from_header(&frame[..HEADER_LENGTH])?;
    if frame.len() > frame_length {
        return Err("PHXP stream contains bytes beyond the declared frame".to_string());
    }
    if frame.len() < frame_length {
        read_exact_part(
            reader,
            &mut frame,
            frame_length,
            "unexpected EOF in PHXP frame payload",
        )?;
    }
    Ok(frame)
}

fn read_exact_part(
    reader: &mut impl Read,
    frame: &mut Vec<u8>,
    target_length: usize,
    eof_message: &str,
) -> Result<(), String> {
    let start = frame.len();
    frame.resize(target_length, 0);
    match reader.read_exact(&mut frame[start..]) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Err(eof_message.to_string()),
        Err(error) => Err(format!("cannot read PHXP frame: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::read_frame;
    use crate::handoff_protocol::{
        HEADER_LENGTH, Handoff, MAX_PACKET_LENGTH, Message, decode, encode,
    };
    use std::io::{self, Cursor, Read};

    struct ChunkedReader {
        bytes: Vec<u8>,
        chunks: Vec<usize>,
        offset: usize,
        chunk: usize,
    }

    impl ChunkedReader {
        fn new(bytes: Vec<u8>, chunks: Vec<usize>) -> Self {
            Self {
                bytes,
                chunks,
                offset: 0,
                chunk: 0,
            }
        }
    }

    impl Read for ChunkedReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let requested = self.chunks.get(self.chunk).copied().unwrap_or(output.len());
            self.chunk += 1;
            let length = requested
                .min(output.len())
                .min(self.bytes.len() - self.offset);
            output[..length].copy_from_slice(&self.bytes[self.offset..self.offset + length]);
            self.offset += length;
            Ok(length)
        }
    }

    #[test]
    fn reads_fixed_frame_one_byte_at_a_time() {
        let packet = encode(&Message::Hello).unwrap();
        let mut reader = ChunkedReader::new(packet.clone(), vec![1; packet.len()]);

        assert_eq!(read_frame(&mut reader).unwrap(), packet);
    }

    #[test]
    fn reads_payload_frame_split_at_every_boundary() {
        let packet = encode(&Message::Handoff(Handoff {
            connection_id: [7; 16],
            peeked_length: 123,
            accepted_at_ns: 456,
            requested_sni: "www.example.test".to_string(),
        }))
        .unwrap();

        for boundary in 1..packet.len() {
            let mut reader =
                ChunkedReader::new(packet.clone(), vec![boundary, packet.len() - boundary]);
            assert_eq!(
                decode(&read_frame(&mut reader).unwrap()).unwrap(),
                decode(&packet).unwrap(),
                "split at byte {boundary}",
            );
        }
    }

    #[test]
    fn rejects_coalesced_frames() {
        let mut bytes = encode(&Message::Hello).unwrap();
        bytes.extend(encode(&Message::Ready).unwrap());

        assert!(read_frame(&mut Cursor::new(bytes)).is_err());
    }

    #[test]
    fn rejects_eof_in_header() {
        let packet = encode(&Message::Hello).unwrap();
        assert!(read_frame(&mut Cursor::new(packet[..HEADER_LENGTH - 1].to_vec())).is_err());
    }

    #[test]
    fn rejects_eof_in_payload() {
        let packet = encode(&Message::Handoff(Handoff {
            connection_id: [8; 16],
            peeked_length: 1,
            accepted_at_ns: 2,
            requested_sni: "example.test".to_string(),
        }))
        .unwrap();
        assert!(read_frame(&mut Cursor::new(packet[..packet.len() - 1].to_vec())).is_err());
    }

    #[test]
    fn rejects_declared_payload_above_limit() {
        let mut header = encode(&Message::Hello).unwrap();
        header[36..38].copy_from_slice(
            &u16::try_from(MAX_PACKET_LENGTH - HEADER_LENGTH + 1)
                .unwrap()
                .to_be_bytes(),
        );

        assert!(read_frame(&mut Cursor::new(header)).is_err());
    }
}
