use dns_parser::Packet as DnsPacket;
use dns_parser::{Class, Opcode, QueryClass, QueryType, ResourceRecord, ResponseCode, RRData};
use serde_json::{Map, Value, to_value};
use serde_json::error::Error;

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
    ttl: u32,
    rdata: String,
}

pub struct DnsHeader<'a> {
    id: u16,
    opcode: String,
    flags: Vec<&'a str>,
    rcode: String,
    total_questions: u16,
    total_answer_rrs: u16,
    total_authority_rrs: u16,
    total_additional_rrs: u16,
    questions: Vec<DnsQuestion>,
    answer_rrs: Vec<DnsResourceRecord>,
    authority_rrs: Vec<DnsResourceRecord>,
    additional_rrs: Vec<DnsResourceRecord>,
}

impl<'a> DnsHeader<'a> {
    pub fn new(p: &DnsPacket) -> DnsHeader<'a> {
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
        if !p.questions.is_empty() {
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
            id: p.header.id,
            opcode: String::from(opcode_string),
            flags: flags,
            rcode: String::from(rcode_string),
            total_questions: p.header.questions,
            total_answer_rrs: p.header.answers,
            total_authority_rrs: p.header.nameservers,
            total_additional_rrs: p.header.additional,
            questions: questions,
            answer_rrs: answers,
            authority_rrs: nameservers,
            additional_rrs: additionals,
        }
    }

    pub fn to_json_map(&self) -> Result<Map<String, Value>, Error> {
        let mut header = Map::new();

        header.insert(String::from("id"), to_value(self.id.to_owned())?);
        header.insert(String::from("opcode"), to_value(self.opcode.to_owned())?);
        header.insert(String::from("flags"), to_value(self.flags.to_owned())?);
        header.insert(String::from("rcode"), to_value(self.rcode.to_owned())?);
        header.insert(
            String::from("total_questions"),
            to_value(self.total_questions.to_owned())?,
        );
        header.insert(
            String::from("total_answer_rrs"),
            to_value(self.total_answer_rrs.to_owned())?,
        );
        header.insert(
            String::from("total_authority_rrs"),
            to_value(self.total_authority_rrs.to_owned())?,
        );
        header.insert(
            String::from("total_additional_rrs"),
            to_value(self.total_additional_rrs.to_owned())?,
        );
        header.insert(String::from("questions"), to_value(&self.questions)?);
        header.insert(String::from("answer_rrs"), to_value(&self.answer_rrs)?);
        header.insert(
            String::from("authority_rrs"),
            to_value(&self.authority_rrs)?,
        );
        header.insert(
            String::from("additional_rrs"),
            to_value(&self.additional_rrs)?,
        );

        Ok(header)
    }

    fn parse_rr(rrs: &Vec<ResourceRecord>) -> Vec<DnsResourceRecord> {
        let mut parsed: Vec<DnsResourceRecord> = Vec::new();
        if !rrs.is_empty() {
            for rr in rrs.iter() {
                let dns_rr = DnsResourceRecord {
                    name: rr.name.to_string(),
                    class: match rr.cls {
                        Class::IN => String::from("IN"),
                        Class::CS => String::from("CS"),
                        Class::CH => String::from("CH"),
                        Class::HS => String::from("HS"),
                    },
                    ttl: rr.ttl,
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
