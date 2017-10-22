use dns_parser::Packet as DnsPacket;
use dns_parser::Opcode;
use serde_json::{Value, Map, Number};

pub struct DnsHeader {
	id: Number,
	opcode: String,
	flags: Value,
	total_questions: Number,
	total_answer_rrs: Number,
	total_authority_rrs: Number,
	total_additional_rrs: Number,
}

impl DnsHeader {
	pub fn new(p: &DnsPacket) -> DnsHeader {
		let opcode_number = p.header.opcode;
		let opcode_string = match opcode_number {
			Opcode::StandardQuery => "QUERY",
			Opcode::InverseQuery => "IQUERY",
			Opcode::ServerStatusRequest => "STATUS",
			_ => "UNKNOWN",
		};

		let mut flags: Vec<&str> = Vec::new();
		if p.header.authoritative {
			flags.push("AA");
		}
		if p.header.truncated {
			flags.push("TC");
		}
		if p.header.recursion_desired {
			flags.push("RD");
		}
		if p.header.recursion_available {
			flags.push("RA");
		}
		if p.header.authenticated_data {
			flags.push("AD");
		}
		if p.header.checking_disabled {
			flags.push("CD");
		}

		DnsHeader {
			id: Number::from(p.header.id),
			opcode: opcode_string.to_string(),
			flags: Value::from(flags),
			total_questions: Number::from(p.header.questions),
			total_answer_rrs: Number::from(p.header.answers),
			total_authority_rrs: Number::from(p.header.nameservers),
			total_additional_rrs: Number::from(p.header.additional),
		}
	}

	pub fn to_json_map(&self) -> Map<String, Value> {
		let mut header = Map::new();

		header.insert("id".to_string(), Value::Number(self.id.clone()));
		header.insert("opcode".to_string(), Value::String(self.opcode.clone()));
		header.insert("flags".to_string(), self.flags.clone());
		header.insert("total_questions".to_string(), Value::Number(self.total_questions.clone()));
		header.insert("total_answer_rrs".to_string(), Value::Number(self.total_answer_rrs.clone()));
		header.insert("total_authority_rrs".to_string(), Value::Number(self.total_authority_rrs.clone()));
		header.insert("total_additional_rrs".to_string(), Value::Number(self.total_additional_rrs.clone()));

		header
	}
}