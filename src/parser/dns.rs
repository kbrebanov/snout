use dns_parser::Packet as DnsPacket;
use dns_parser::Opcode;
use serde_json::{Value, Map, Number};

pub struct DnsHeader {
	id: Number,
	opcode: String,
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

		DnsHeader {
			id: Number::from(p.header.id),
			opcode: opcode_string.to_string(),
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
		header.insert("total_questions".to_string(), Value::Number(self.total_questions.clone()));
		header.insert("total_answer_rrs".to_string(), Value::Number(self.total_answer_rrs.clone()));
		header.insert("total_authority_rrs".to_string(), Value::Number(self.total_authority_rrs.clone()));
		header.insert("total_additional_rrs".to_string(), Value::Number(self.total_additional_rrs.clone()));

		header
	}
}