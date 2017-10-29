use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use serde_json::{Map, Value, to_value};
use serde_json::error::Error;

pub struct Ipv4Header<'a> {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    total_length: u16,
    identification: u16,
    flags: Vec<&'a str>,
    fragment_offset: u16,
    ttl: u8,
    next_level_protocol: String,
    checksum: u16,
    source: String,
    destination: String,
}

impl<'a> Ipv4Header<'a> {
    pub fn new(p: &Ipv4Packet) -> Ipv4Header<'a> {
        let flags_number = p.get_flags();
        let mut flags: Vec<&str> = Vec::new();

        if (flags_number & Ipv4Flags::DontFragment) == Ipv4Flags::DontFragment {
            flags.push("DF");
        }
        if (flags_number & Ipv4Flags::MoreFragments) == Ipv4Flags::MoreFragments {
            flags.push("MF");
        }

        Ipv4Header {
            version: p.get_version(),
            ihl: p.get_header_length(),
            dscp: p.get_dscp(),
            ecn: p.get_ecn(),
            total_length: p.get_total_length(),
            identification: p.get_identification(),
            flags: flags,
            fragment_offset: p.get_fragment_offset(),
            ttl: p.get_ttl(),
            next_level_protocol: p.get_next_level_protocol().to_string().to_lowercase(),
            checksum: p.get_checksum(),
            source: p.get_source().to_string(),
            destination: p.get_destination().to_string(),
        }
    }

    pub fn to_json_map(&self) -> Result<Map<String, Value>, Error> {
        let mut header = Map::new();

        header.insert(String::from("version"), to_value(self.version.to_owned())?);
        header.insert(String::from("ihl"), to_value(self.ihl.to_owned())?);
        header.insert(String::from("dscp"), to_value(self.dscp.to_owned())?);
        header.insert(String::from("ecn"), to_value(self.ecn.to_owned())?);
        header.insert(
            String::from("total_length"),
            to_value(self.total_length.to_owned())?,
        );
        header.insert(
            String::from("identification"),
            to_value(self.identification.to_owned())?,
        );
        header.insert(String::from("flags"), to_value(self.flags.to_owned())?);
        header.insert(
            String::from("fragment_offset"),
            to_value(self.fragment_offset.to_owned())?,
        );
        header.insert(String::from("ttl"), to_value(self.ttl.to_owned())?);
        header.insert(
            String::from("protocol"),
            to_value(self.next_level_protocol.to_owned())?,
        );
        header.insert(
            String::from("checksum"),
            to_value(self.checksum.to_owned())?,
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
