use pnet::packet::ethernet::EthernetPacket;
use serde_json::{Map, Value, to_value};
use serde_json::error::Error;

pub struct EthernetHeader {
    source: String,
    destination: String,
    ethertype: String,
}

impl EthernetHeader {
    pub fn new(p: &EthernetPacket) -> EthernetHeader {
        EthernetHeader {
            source: p.get_source().to_string(),
            destination: p.get_destination().to_string(),
            ethertype: p.get_ethertype().to_string().to_lowercase(),
        }
    }

    pub fn to_json_map(&self) -> Result<Map<String, Value>, Error> {
        let mut header = Map::new();

        header.insert(String::from("source"), to_value(self.source.to_owned())?);
        header.insert(
            String::from("destination"),
            to_value(self.destination.to_owned())?,
        );
        header.insert(String::from("type"), to_value(self.ethertype.to_owned())?);

        Ok(header)
    }
}
