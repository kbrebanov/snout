use pnet::packet::ipv4::{Ipv4Packet, Ipv4Flags};
use serde_json::{Value, Map, Number};

pub struct Ipv4Header {
	version: Number,
	ihl: Number,
	dscp: Number,
	ecn: Number,
	total_length: Number,
	identification: Number,
	flags: Value,
	fragment_offset: Number,
	ttl: Number,
	next_level_protocol: String,
	checksum: Number,
	source: String,
	destination: String,
}

impl Ipv4Header {
	pub fn new(p: &Ipv4Packet) -> Ipv4Header {
		let flags_number = p.get_flags();
		let mut flags: Vec<&str> = Vec::new();

		if (flags_number & Ipv4Flags::DontFragment) == Ipv4Flags::DontFragment {
			flags.push("DF");
		}
		if (flags_number & Ipv4Flags::MoreFragments) == Ipv4Flags::MoreFragments {
			flags.push("MF");
		}

		Ipv4Header {
			version: Number::from(p.get_version()),
			ihl: Number::from(p.get_header_length()),
			dscp: Number::from(p.get_dscp()),
			ecn: Number::from(p.get_ecn()),
			total_length: Number::from(p.get_total_length()),
			identification: Number::from(p.get_identification()),
			flags: Value::from(flags),
			//flags: Number::from(p.get_flags()),
			fragment_offset: Number::from(p.get_fragment_offset()),
			ttl: Number::from(p.get_ttl()),
			next_level_protocol: p.get_next_level_protocol().to_string().to_lowercase(),
			checksum: Number::from(p.get_checksum()),
			source: p.get_source().to_string(),
			destination: p.get_destination().to_string(),
		}
	}

	pub fn to_json_map(&self) -> Map<String, Value> {
		let mut header = Map::new();

    	header.insert("version".to_string(), Value::Number(self.version.clone()));
    	header.insert("ihl".to_string(), Value::Number(self.ihl.clone()));
    	header.insert("dscp".to_string(), Value::Number(self.dscp.clone()));
    	header.insert("ecn".to_string(), Value::Number(self.ecn.clone()));
    	header.insert("total_length".to_string(), Value::Number(self.total_length.clone()));
    	header.insert("identification".to_string(), Value::Number(self.identification.clone()));
		header.insert("flags".to_string(), self.flags.clone());
    	//header.insert("flags.".to_string(), Value::Number(self.flags.clone()));
    	header.insert("fragment_offset".to_string(), Value::Number(self.fragment_offset.clone()));
    	header.insert("ttl".to_string(), Value::Number(self.ttl.clone()));
    	header.insert("protocol".to_string(), Value::String(self.next_level_protocol.clone()));
    	header.insert("checksum".to_string(), Value::Number(self.checksum.clone()));
    	header.insert("source_address".to_string(), Value::String(self.source.clone()));
    	header.insert("destination_address".to_string(), Value::String(self.destination.clone()));
    
		header
	}
}