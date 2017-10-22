use dns_parser::Packet as DnsPacket;
use dns_parser::{Opcode, ResponseCode, QueryType, QueryClass, Class, RRData, ResourceRecord};
use serde_json::{Value, Map, Number, to_value};

#[derive(Serialize)]
pub struct DnsQuestion {
	name: String,
	qtype: String,
	qclass: String,
}

#[derive(Serialize)]
pub struct DnsResourceRecord {
	name: String,
	class: String,
	ttl: Number,
	rdata: String,
}

pub struct DnsHeader {
	id: Number,
	opcode: String,
	flags: Value,
	rcode: String,
	total_questions: Number,
	total_answer_rrs: Number,
	total_authority_rrs: Number,
	total_additional_rrs: Number,
	questions: Value,
	answer_rrs: Value,
	authority_rrs: Value,
	additional_rrs: Value,
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

		let rcode_number = p.header.response_code;
		let rcode_string = match rcode_number {
			ResponseCode::NoError => "NOERROR",
			ResponseCode::FormatError => "FORMERR",
			ResponseCode::ServerFailure => "SERVFAIL",
			ResponseCode::NameError => "NXDOMAIN",
			ResponseCode::NotImplemented => "NOTIMPL",
			ResponseCode::Refused => "REFUSED",
			_ => "UNKNOWN",
		};

		let mut questions: Vec<DnsQuestion> = Vec::new();
		if ! p.questions.is_empty() {
			for q in p.questions.iter() {
				let question = DnsQuestion {
					name: q.qname.to_string(),
					qtype: match q.qtype {
						QueryType::A => String::from("A"),
						QueryType::NS => String::from("NS"),
						QueryType::MF => String::from("MF"),
						QueryType::CNAME => String::from("CNAME"),
						QueryType::SOA => String::from("SOA"),
						QueryType::MB => String::from("MB"),
						QueryType::MG => String::from("MG"),
						QueryType::MR => String::from("MR"),
						QueryType::NULL => String::from("NULL"),
						QueryType::WKS => String::from("WKS"),
						QueryType::PTR => String::from("PTR"),
						QueryType::HINFO => String::from("HINFO"),
						QueryType::MINFO => String::from("MINFO"),
						QueryType::MX => String::from("MX"),
						QueryType::TXT => String::from("TXT"),
						QueryType::AAAA => String::from("AAAA"),
						QueryType::SRV => String::from("SRV"),
						QueryType::AXFR => String::from("AXFR"),
						QueryType::MAILB => String::from("MAILB"),
						QueryType::MAILA => String::from("MAILA"),
						QueryType::All => String::from("ALL"),
					},
					qclass: match q.qclass {
						QueryClass::IN => String::from("IN"),
						QueryClass::CS => String::from("CS"),
						QueryClass::CH => String::from("CH"),
						QueryClass::HS => String::from("HS"),
						QueryClass::Any => String::from("ANY"),
					},
				};
				questions.push(question);
			}
		}

		let answers = DnsHeader::parse_rr(&p.answers);

		let nameservers = DnsHeader::parse_rr(&p.nameservers);

		let additionals = DnsHeader::parse_rr(&p.additional);

		DnsHeader {
			id: Number::from(p.header.id),
			opcode: opcode_string.to_string(),
			flags: Value::from(flags),
			rcode: rcode_string.to_string(),
			total_questions: Number::from(p.header.questions),
			total_answer_rrs: Number::from(p.header.answers),
			total_authority_rrs: Number::from(p.header.nameservers),
			total_additional_rrs: Number::from(p.header.additional),
			questions: to_value(questions).unwrap(),
			answer_rrs: to_value(answers).unwrap(),
			authority_rrs: to_value(nameservers).unwrap(),
			additional_rrs: to_value(additionals).unwrap(),
		}
	}

	pub fn to_json_map(&self) -> Map<String, Value> {
		let mut header = Map::new();

		header.insert("id".to_string(), Value::Number(self.id.clone()));
		header.insert("opcode".to_string(), Value::String(self.opcode.clone()));
		header.insert("flags".to_string(), self.flags.clone());
		header.insert("rcode".to_string(), Value::String(self.rcode.clone()));
		header.insert("total_questions".to_string(), Value::Number(self.total_questions.clone()));
		header.insert("total_answer_rrs".to_string(), Value::Number(self.total_answer_rrs.clone()));
		header.insert("total_authority_rrs".to_string(), Value::Number(self.total_authority_rrs.clone()));
		header.insert("total_additional_rrs".to_string(), Value::Number(self.total_additional_rrs.clone()));
		header.insert("questions".to_string(), self.questions.clone());
		header.insert("answer_rrs".to_string(), self.answer_rrs.clone());
		header.insert("authority_rrs".to_string(), self.authority_rrs.clone());
		header.insert("additional_rrs".to_string(), self.additional_rrs.clone());

		header
	}

	fn parse_rr(rrs: &Vec<ResourceRecord>) -> Vec<DnsResourceRecord> {
		let mut parsed: Vec<DnsResourceRecord> = Vec::new();
		if ! rrs.is_empty() {
			for rr in rrs.iter() {
				let dns_rr = DnsResourceRecord {
					name: rr.name.to_string(),
					class: match rr.cls {
						Class::IN => String::from("IN"),
						Class::CS => String::from("CS"),
						Class::CH => String::from("CH"),
						Class::HS => String::from("HS"),
					},
					ttl: Number::from(rr.ttl),
					rdata: match rr.data {
						RRData::CNAME(cname) => cname.to_string(),
						RRData::NS(ns) => ns.to_string(),
						RRData::PTR(ptr) => ptr.to_string(),
						RRData::TXT(ref txt) => txt.clone(),
						_ => String::from("Unknown"),
					},
				};
				parsed.push(dns_rr);
			}
		}
		parsed
	}
}