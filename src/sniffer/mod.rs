use pcap::Capture;
use serde_json;
use parser;

pub fn sniff(interface: &str, promiscuous: bool, snaplen: i32, timeout: i32, filter: &str) {
    let mut capture = Capture::from_device(interface).unwrap()
                      	.promisc(promiscuous)
                        .snaplen(snaplen)
                        .timeout(timeout)
                        .open()
                        .unwrap();

    if !filter.is_empty() {
    	capture.filter(filter).unwrap();
    }

    while let Ok(packet) = capture.next() {
    	let packet_headers = parser::parse_headers(packet);
		  println!("{}", serde_json::to_string(&packet_headers).unwrap());
    }
    println!();
}