use pnet::packet::tcp::{TcpFlags, TcpPacket};
use serde_json::{Map, Value, to_value};
use serde_json::error::Error;

pub struct TcpHeader<'a> {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    ack_number: u32,
    data_offset: u8,
    flags: Vec<&'a str>,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

impl<'a> TcpHeader<'a> {
    pub fn new(p: &TcpPacket) -> TcpHeader<'a> {
        let flags_number = p.get_flags();
        let mut flags: Vec<&str> = Vec::new();

        if (flags_number & TcpFlags::ACK) == TcpFlags::ACK {
            flags.push("ACK")
        }
        if (flags_number & TcpFlags::CWR) == TcpFlags::CWR {
            flags.push("CWR")
        }
        if (flags_number & TcpFlags::ECE) == TcpFlags::ECE {
            flags.push("ECE")
        }
        if (flags_number & TcpFlags::FIN) == TcpFlags::FIN {
            flags.push("FIN")
        }
        if (flags_number & TcpFlags::NS) == TcpFlags::NS {
            flags.push("NS")
        }
        if (flags_number & TcpFlags::PSH) == TcpFlags::PSH {
            flags.push("PSH")
        }
        if (flags_number & TcpFlags::RST) == TcpFlags::RST {
            flags.push("RST")
        }
        if (flags_number & TcpFlags::SYN) == TcpFlags::SYN {
            flags.push("SYN")
        }
        if (flags_number & TcpFlags::URG) == TcpFlags::URG {
            flags.push("URG")
        }

        TcpHeader {
            source_port: p.get_source(),
            destination_port: p.get_destination(),
            sequence_number: p.get_sequence(),
            ack_number: p.get_acknowledgement(),
            data_offset: p.get_data_offset(),
            flags: flags,
            window_size: p.get_window(),
            checksum: p.get_checksum(),
            urgent_pointer: p.get_urgent_ptr(),
        }
    }

    pub fn to_json_map(&self) -> Result<Map<String, Value>, Error> {
        let mut header = Map::new();

        header.insert(
            String::from("source_port"),
            to_value(self.source_port.to_owned())?,
        );
        header.insert(
            String::from("destination_port"),
            to_value(self.destination_port.to_owned())?,
        );
        header.insert(
            String::from("sequence_number"),
            to_value(self.sequence_number.to_owned())?,
        );
        header.insert(
            String::from("ack_number"),
            to_value(self.ack_number.to_owned())?,
        );
        header.insert(
            String::from("data_offset"),
            to_value(self.data_offset.to_owned())?,
        );
        header.insert(String::from("flags"), to_value(self.flags.to_owned())?);
        header.insert(
            String::from("window_size"),
            to_value(self.window_size.to_owned())?,
        );
        header.insert(
            String::from("checksum"),
            to_value(self.checksum.to_owned())?,
        );
        header.insert(
            String::from("urgent_pointer"),
            to_value(self.urgent_pointer.to_owned())?,
        );

        Ok(header)
    }
}
