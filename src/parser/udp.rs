use pnet::packet::udp::UdpPacket;
use serde_json::{Map, Value, to_value};
use serde_json::error::Error;

pub struct UdpHeader {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
}

impl UdpHeader {
    pub fn new(p: &UdpPacket) -> UdpHeader {
        UdpHeader {
            source_port: p.get_source(),
            destination_port: p.get_destination(),
            length: p.get_length(),
            checksum: p.get_checksum(),
        }
    }

    pub fn to_json_map(&self) -> Result<Map<String, Value>, Error> {
        let mut header = Map::new();

        header.insert(
            String::from("source_port"),
            to_value(self.source_port.to_owned())?,
        );
        header.insert(
            String::from("destination_port"),
            to_value(self.destination_port.to_owned())?,
        );
        header.insert(String::from("length"), to_value(self.length.to_owned())?);
        header.insert(
            String::from("checksum"),
            to_value(self.checksum.to_owned())?,
        );

        Ok(header)
    }
}
