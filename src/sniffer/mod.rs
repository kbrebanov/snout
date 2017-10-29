use futures::stream::Stream;
use pcap::{Capture, Device, Error, Packet};
use pcap::tokio::PacketCodec;
use serde_json::to_string;
use tokio_core::reactor::Core;

use parser;

struct JsonDumpCodec {}

impl PacketCodec for JsonDumpCodec {
    type Type = String;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, Error> {
        let packet_headers = parser::parse_headers(packet).unwrap();
        let p = to_string(&packet_headers).unwrap();
        Ok(p)
    }
}

pub fn sniff(interface: &str, promiscuous: bool, snaplen: i32, timeout: i32, filter: &str) -> Result<(), Error> {
    let mut core = Core::new()?;
    let handle = core.handle();
    let mut capture = Capture::from_device(interface)?
        .promisc(promiscuous)
        .snaplen(snaplen)
        .timeout(timeout)
        .open()?
        .setnonblock()?;

    if !filter.is_empty() {
        capture.filter(filter)?;
    }

    let s = capture.stream(&handle, JsonDumpCodec {})?;
    let done = s.for_each(move |s| {
        println!("{}", s);
        Ok(())
    });

    core.run(done)?;

    Ok(())
}

pub fn list_interfaces() -> Result<(), Error> {
    let interfaces = Device::list()?;

    for interface in interfaces.iter() {
        println!("{}", interface.name);
    }

    Ok(())
}
