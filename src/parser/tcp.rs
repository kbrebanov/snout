use pnet::packet::tcp::TcpPacket;
use serde_json::{Value, Map, Number};

pub struct TcpHeader {
	source_port: Number,
	destination_port: Number,
	sequence_number: Number,
	ack_number: Number,
	data_offset: Number,
	flags: Number,
	window_size: Number,
	checksum: Number,
	urgent_pointer: Number,
}

impl TcpHeader {
	pub fn new(p: &TcpPacket) -> TcpHeader {
		TcpHeader {
			source_port: Number::from(p.get_source()),
			destination_port: Number::from(p.get_destination()),
			sequence_number: Number::from(p.get_sequence()),
			ack_number: Number::from(p.get_acknowledgement()),
			data_offset: Number::from(p.get_data_offset()),
			flags: Number::from(p.get_flags()),
			window_size: Number::from(p.get_window()),
			checksum: Number::from(p.get_checksum()),
			urgent_pointer: Number::from(p.get_urgent_ptr()),	
		}
	}

	pub fn to_json_map(&self) -> Map<String, Value> {
		let mut header = Map::new();

		header.insert("source_port".to_string(), Value::Number(self.source_port.clone()));
		header.insert("destination_port".to_string(), Value::Number(self.destination_port.clone()));
		header.insert("sequence_number".to_string(), Value::Number(self.sequence_number.clone()));
		header.insert("ack_number".to_string(), Value::Number(self.ack_number.clone()));
		header.insert("data_offset".to_string(), Value::Number(self.data_offset.clone()));
		header.insert("flags".to_string(), Value::Number(self.flags.clone()));
		header.insert("window_size".to_string(), Value::Number(self.window_size.clone()));
		header.insert("checksum".to_string(), Value::Number(self.checksum.clone()));
		header.insert("urgent_pointer".to_string(), Value::Number(self.urgent_pointer.clone()));

		header
	}
}