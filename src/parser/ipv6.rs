use pnet::packet::ipv6::Ipv6Packet;
use serde_json::{Map, Value, to_value};
use serde_json::error::Error;

pub struct Ipv6Header {
    version: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_length: u16,
    next_header: String,
    hop_limit: u8,
    source: String,
    destination: String,
}

impl Ipv6Header {
    pub fn new(p: &Ipv6Packet) -> Ipv6Header {
        Ipv6Header {
            version: p.get_version(),
            traffic_class: p.get_traffic_class(),
            flow_label: p.get_flow_label(),
            payload_length: p.get_payload_length(),
            next_header: p.get_next_header().to_string(),
            hop_limit: p.get_hop_limit(),
            source: p.get_source().to_string(),
            destination: p.get_destination().to_string(),
        }
    }

    pub fn to_json_map(&self) -> Result<Map<String, Value>, Error> {
        let mut header = Map::new();

        header.insert(String::from("version"), to_value(self.version.to_owned())?);
        header.insert(
            String::from("traffic_class"),
            to_value(self.traffic_class.to_owned())?,
        );
        header.insert(
            String::from("flow_label"),
            to_value(self.flow_label.to_owned())?,
        );
        header.insert(
            String::from("payload_length"),
            to_value(self.payload_length.to_owned())?,
        );
        header.insert(
            String::from("next_header"),
            to_value(self.next_header.to_owned())?,
        );
        header.insert(
            String::from("hop_limit"),
            to_value(self.hop_limit.to_owned())?,
        );
        header.insert(
            String::from("source_address"),
            to_value(self.source.to_owned())?,
        );
        header.insert(
            String::from("destination_address"),
            to_value(self.destination.to_owned())?,
        );

        Ok(header)
    }
}
