use bytes::{Buf, BufMut};

use codec::Codec;

#[derive(Clone, Debug, PartialEq)]
pub struct ClientTransportParameters {
    pub initial_version: u32,
    pub parameters: TransportParameters,
}

impl Codec for ClientTransportParameters {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u32_be(self.initial_version);
        self.parameters.encode(buf);
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        ClientTransportParameters {
            initial_version: buf.get_u32_be(),
            parameters: TransportParameters::decode(buf),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerTransportParameters {
    pub negotiated_version: u32,
    pub supported_versions: Vec<u32>,
    pub parameters: TransportParameters,
}

impl Codec for ServerTransportParameters {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        buf.put_u32_be(self.negotiated_version);
        buf.put_u8((4 * self.supported_versions.len()) as u8);
        for v in self.supported_versions.iter() {
            buf.put_u32_be(*v);
        }
        self.parameters.encode(buf);
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        ServerTransportParameters {
            negotiated_version: buf.get_u32_be(),
            supported_versions: {
                let mut supported_versions = vec![];
                let supported_bytes = buf.get_u8() as usize;
                let mut sub = buf.take(supported_bytes);
                while sub.has_remaining() {
                    supported_versions.push(sub.get_u32_be());
                }
                supported_versions
            },
            parameters: TransportParameters::decode(buf),
        }
    }
}

impl Codec for TransportParameters {
    fn encode<T: BufMut>(&self, buf: &mut T) {
        let mut tmp = vec![];
        let mut val = vec![];

        tmp.put_u16_be(0);
        val.put_u32_be(self.max_stream_data);
        tmp.put_u16_be(val.len() as u16);
        tmp.append(&mut val);
        val.truncate(0);

        tmp.put_u16_be(1);
        val.put_u32_be(self.max_data);
        tmp.put_u16_be(val.len() as u16);
        tmp.append(&mut val);
        val.truncate(0);

        tmp.put_u16_be(3);
        val.put_u16_be(self.idle_timeout);
        tmp.put_u16_be(val.len() as u16);
        tmp.append(&mut val);
        val.truncate(0);

        if self.max_streams_bidi > 0 {
            tmp.put_u16_be(2);
            val.put_u16_be(self.max_streams_bidi);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if self.max_packet_size != 65527 {
            tmp.put_u16_be(5);
            val.put_u16_be(self.max_packet_size);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if self.ack_delay_exponent != 3 {
            tmp.put_u16_be(7);
            val.put_u8(self.ack_delay_exponent);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if self.max_stream_id_uni > 0 {
            tmp.put_u16_be(8);
            val.put_u16_be(self.max_stream_id_uni);
            tmp.put_u16_be(val.len() as u16);
            tmp.append(&mut val);
            val.truncate(0);
        }

        if let Some(token) = self.stateless_reset_token {
            tmp.put_u16_be(6);
            tmp.put_u16_be(16);
            tmp.extend_from_slice(&token);
        }

        buf.put_u16_be(tmp.len() as u16);
        buf.put_slice(&tmp);
    }

    fn decode<T: Buf>(buf: &mut T) -> Self {
        let mut params = TransportParameters::default();
        let num = buf.get_u16_be();
        let mut sub = buf.take(num as usize);
        while sub.has_remaining() {
            let tag = sub.get_u16_be();
            let size = sub.get_u16_be();
            match tag {
                0 => {
                    debug_assert_eq!(size, 4);
                    params.max_stream_data = sub.get_u32_be();
                }
                1 => {
                    debug_assert_eq!(size, 4);
                    params.max_data = sub.get_u32_be();
                }
                2 => {
                    debug_assert_eq!(size, 2);
                    params.max_streams_bidi = sub.get_u16_be();
                }
                3 => {
                    debug_assert_eq!(size, 2);
                    params.idle_timeout = sub.get_u16_be();
                }
                5 => {
                    debug_assert_eq!(size, 2);
                    params.max_packet_size = sub.get_u16_be();
                }
                6 => {
                    debug_assert_eq!(size, 16);
                    let mut token = [0; 16];
                    sub.copy_to_slice(&mut token);
                    params.stateless_reset_token = Some(token);
                }
                7 => {
                    debug_assert_eq!(size, 1);
                    params.ack_delay_exponent = sub.get_u8();
                }
                8 => {
                    debug_assert_eq!(size, 2);
                    params.max_stream_id_uni = sub.get_u16_be();
                }
                t => panic!("invalid transport parameter tag {}", t),
            }
        }
        params
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransportParameters {
    pub max_stream_data: u32,                    // 0x00
    pub max_data: u32,                           // 0x01
    pub max_streams_bidi: u16,                   // 0x02
    pub idle_timeout: u16,                       // 0x03
    pub max_packet_size: u16,                    // 0x05
    pub stateless_reset_token: Option<[u8; 16]>, // 0x06
    pub ack_delay_exponent: u8,                  // 0x07
    pub max_stream_id_uni: u16,                  // 0x08
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            max_stream_data: 131072,
            max_data: 1048576,
            max_streams_bidi: 4,
            idle_timeout: 300,
            max_packet_size: 65527,
            stateless_reset_token: None,
            ack_delay_exponent: 3,
            max_stream_id_uni: 20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TransportParameters;
    use super::{ClientTransportParameters, Codec, ServerTransportParameters};
    use std::fmt::Debug;
    use std::io::Cursor;

    fn round_trip<T: Codec + PartialEq + Debug>(t: T) {
        let buf = {
            let mut ret = Vec::new();
            t.encode(&mut ret);
            ret
        };
        let mut read = Cursor::new(&buf);
        assert_eq!(t, T::decode(&mut read));
    }

    #[test]
    fn test_client_transport_parameters() {
        round_trip(ClientTransportParameters {
            initial_version: 1,
            parameters: TransportParameters {
                max_stream_data: 0,
                max_data: 1234,
                idle_timeout: 26,
                ..Default::default()
            },
        });
    }

    #[test]
    fn test_server_transport_parameters() {
        round_trip(ServerTransportParameters {
            negotiated_version: 1,
            supported_versions: vec![1, 2, 3],
            parameters: TransportParameters {
                stateless_reset_token: Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                ..Default::default()
            },
        });
    }
}
