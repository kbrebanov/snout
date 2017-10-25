use pnet::packet::ipv6::Ipv6Packet;
use serde_json::{Value, Map, Number};

pub struct Ipv6Header {
    version: Number,
    traffic_class: Number,
    flow_label: Number,
    payload_length: Number,
    next_header: String,
    hop_limit: Number,
    source: String,
    destination: String,
}

impl Ipv6Header {
    pub fn new(p: &Ipv6Packet) -> Ipv6Header {
        Ipv6Header {
            version: Number::from(p.get_version()),
            traffic_class: Number::from(p.get_traffic_class()),
            flow_label: Number::from(p.get_flow_label()),
            payload_length: Number::from(p.get_payload_length()),
            next_header: p.get_next_header().to_string(),
            hop_limit: Number::from(p.get_hop_limit()),
            source: p.get_source().to_string(),
            destination: p.get_destination().to_string(),
        }
    }

    pub fn to_json_map(&self) -> Map<String, Value> {
        let mut header = Map::new();

        header.insert("version".to_string(), Value::Number(self.version.clone()));
        header.insert("traffic_class".to_string(), Value::Number(self.traffic_class.clone()));
        header.insert("flow_label".to_string(), Value::Number(self.flow_label.clone()));
        header.insert("payload_length".to_string(), Value::Number(self.payload_length.clone()));
        header.insert("next_header".to_string(), Value::String(self.next_header.clone()));
        header.insert("hop_limit".to_string(), Value::Number(self.hop_limit.clone()));
        header.insert("source_address".to_string(), Value::String(self.source.clone()));
        header.insert("destination_address".to_string(), Value::String(self.destination.clone()));

        header
    }
}
