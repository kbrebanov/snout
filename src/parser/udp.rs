use pnet::packet::udp::UdpPacket;
use serde_json::{Value, Map, Number};

pub struct UdpHeader {
    source_port: Number,
    destination_port: Number,
    length: Number,
    checksum: Number,
}

impl UdpHeader {
    pub fn new(p: &UdpPacket) -> UdpHeader {
        UdpHeader {
            source_port: Number::from(p.get_source()),
            destination_port: Number::from(p.get_destination()),
            length: Number::from(p.get_length()),
            checksum: Number::from(p.get_checksum()),
        }
    }

    pub fn to_json_map(&self) -> Map<String, Value> {
        let mut header = Map::new();

        header.insert(
            "source_port".to_string(),
            Value::Number(self.source_port.clone()),
        );
        header.insert(
            "destination_port".to_string(),
            Value::Number(self.destination_port.clone()),
        );
        header.insert("length".to_string(), Value::Number(self.length.clone()));
        header.insert("checksum".to_string(), Value::Number(self.checksum.clone()));

        header
    }
}
