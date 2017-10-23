use pcap::{Capture, Packet, Error, Device};
use pcap::tokio::PacketCodec;
use serde_json;
use parser;
use tokio_core::reactor::Core;
use futures::stream::Stream;

struct JsonDumpCodec {}

impl PacketCodec for JsonDumpCodec {
    type Type = String;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, Error> {
        let packet_headers = parser::parse_headers(packet);
        let p = serde_json::to_string(&packet_headers).unwrap();
        Ok(p)
    }
}

pub fn sniff(interface: &str, promiscuous: bool, snaplen: i32, timeout: i32, filter: &str) {
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let mut capture = Capture::from_device(interface).unwrap()
                      	.promisc(promiscuous)
                        .snaplen(snaplen)
                        .timeout(timeout)
                        .open()
                        .unwrap()
                        .setnonblock()
                        .unwrap();

    if !filter.is_empty() {
    	capture.filter(filter).unwrap();
    }

    let s = capture.stream(&handle, JsonDumpCodec{}).unwrap();
    let done = s.for_each(move |s| {
        println!("{}", s);
        Ok(())
    });

    core.run(done).unwrap();
}

pub fn list_interfaces() {
    let interfaces = Device::list().unwrap();

    for interface in interfaces.iter() {
        println!("{}", interface.name);
    }
}