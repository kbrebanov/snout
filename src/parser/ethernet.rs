use pnet::packet::ethernet;
use serde_json::{Value, Map};

pub struct EthernetHeader {
	source: String,
	destination: String,
	ethertype: String,
}

impl EthernetHeader {
	pub fn new(p: &ethernet::EthernetPacket) -> EthernetHeader {
		EthernetHeader {
			source: p.get_source().to_string(),
			destination: p.get_destination().to_string(),
			ethertype: p.get_ethertype().to_string().to_lowercase(), 	
    	}
	}

	pub fn to_json_map(&self) -> Map<String, Value> {
		let mut header = Map::new();

		header.insert("source".to_string(), Value::String(self.source.clone()));
		header.insert("destination".to_string(), Value::String(self.destination.clone()));
		header.insert("type".to_string(), Value::String(self.ethertype.clone()));

		header
	}
}