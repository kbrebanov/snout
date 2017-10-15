extern crate clap;
extern crate pcap;
extern crate pnet;
extern crate serde_json;

use clap::{Arg, App};
use pcap::Capture;
use pnet::packet::{Packet, ethernet, ip, ipv4, tcp, udp};
use serde_json::{Value, Map, Number};

fn parse_ethernet(p: &ethernet::EthernetPacket) -> Map<String, Value> {
	let source = p.get_source();
	let destination = p.get_destination();
	let ethertype = p.get_ethertype();

	let mut header = Map::new();
	header.insert("source".to_string(), Value::String(source.to_string()));
	header.insert("destination".to_string(), Value::String(destination.to_string()));
	header.insert("type".to_string(), Value::String(ethertype.to_string()));

	header
}

fn parse_ipv4(p: &ipv4::Ipv4Packet) -> Map<String, Value> {
	let version = p.get_version();
	let ihl = p.get_header_length();
	let dscp = p.get_dscp();
	let ecn = p.get_ecn();
	let total_length = p.get_total_length();
	let identification = p.get_identification();
	let flags = p.get_flags();
	let fragment_offset = p.get_fragment_offset();
	let ttl = p.get_ttl();
	let next_level_protocol = p.get_next_level_protocol();
	let checksum = p.get_checksum();
	let source = p.get_source();
	let destination = p.get_destination();

	let mut header = Map::new();
    header.insert("version".to_string(), Value::Number(Number::from(version)));
    header.insert("ihl".to_string(), Value::Number(Number::from(ihl)));
    header.insert("dscp".to_string(), Value::Number(Number::from(dscp)));
    header.insert("ecn".to_string(), Value::Number(Number::from(ecn)));
    header.insert("total_length".to_string(), Value::Number(Number::from(total_length)));
    header.insert("identification".to_string(), Value::Number(Number::from(identification)));
    header.insert("flags.".to_string(), Value::Number(Number::from(flags)));
    header.insert("fragment_offset".to_string(), Value::Number(Number::from(fragment_offset)));
    header.insert("ttl".to_string(), Value::Number(Number::from(ttl)));
    header.insert("protocol".to_string(), Value::String(next_level_protocol.to_string().to_lowercase()));
    header.insert("checksum".to_string(), Value::Number(Number::from(checksum)));
    header.insert("source_address".to_string(), Value::String(source.to_string()));
    header.insert("destination_address".to_string(), Value::String(destination.to_string()));
    
	header
}

fn parse_tcp(p: &tcp::TcpPacket) -> Map<String, Value> {
	let source_port = p.get_source();
	let destination_port = p.get_destination();
	let sequence_number = p.get_sequence();
	let ack_number = p.get_acknowledgement();
	let data_offset = p.get_data_offset();
	let flags = p.get_flags();
	let window_size = p.get_window();
	let checksum = p.get_checksum();
	let urgent_pointer = p.get_urgent_ptr();

	let mut header = Map::new();
	header.insert("source_port".to_string(), Value::String(source_port.to_string()));
	header.insert("destination_port".to_string(), Value::String(destination_port.to_string()));
	header.insert("sequence_number".to_string(), Value::Number(Number::from(sequence_number)));
	header.insert("ack_number".to_string(), Value::Number(Number::from(ack_number)));
	header.insert("data_offset".to_string(), Value::Number(Number::from(data_offset)));
	header.insert("flags".to_string(), Value::Number(Number::from(flags)));
	header.insert("window_size".to_string(), Value::Number(Number::from(window_size)));
	header.insert("checksum".to_string(), Value::Number(Number::from(checksum)));
	header.insert("urgent_pointer".to_string(), Value::Number(Number::from(urgent_pointer)));

	header
}

fn parse_udp(p: &udp::UdpPacket) -> Map<String, Value> {
	let source_port = p.get_source();
	let destination_port = p.get_destination();
	let length = p.get_length();
	let checksum = p.get_checksum();
	        				
	let mut header = Map::new();
	header.insert("source_port".to_string(), Value::String(source_port.to_string()));
	header.insert("destination_port".to_string(), Value::String(destination_port.to_string()));
	header.insert("length".to_string(), Value::Number(Number::from(length)));
	header.insert("checksum".to_string(), Value::Number(Number::from(checksum)));

	header
}

fn parse_headers(p: pcap::Packet) -> Map<String, Value> {
	let mut headers = Map::new();
	    	
	let timestamp = p.header.ts.tv_sec;
	        
	let ethernet_packet = ethernet::EthernetPacket::new(p.data).unwrap();
	        let ethernet_header = parse_ethernet(&ethernet_packet);
	        
	        match ethernet_packet.get_ethertype() {
	        	ethernet::EtherTypes::Ipv4 => {
	        		let ipv4_packet = ipv4::Ipv4Packet::new(ethernet_packet.payload()).unwrap();
	        		let ipv4_header = parse_ipv4(&ipv4_packet);
	        		
	        		match ipv4_packet.get_next_level_protocol() {
	        			ip::IpNextHeaderProtocols::Tcp => {
	        				let tcp_packet = tcp::TcpPacket::new(ipv4_packet.payload()).unwrap();
	        				let tcp_header = parse_tcp(&tcp_packet);
	        				headers.insert("tcp".to_string(), Value::Object(tcp_header));
	        			},
	        			ip::IpNextHeaderProtocols::Udp => {
	        				let udp_packet = udp::UdpPacket::new(ipv4_packet.payload()).unwrap();
	        				let udp_header = parse_udp(&udp_packet);
	        				headers.insert("udp".to_string(), Value::Object(udp_header));
	        			},
	        			_ => (),
	        		}
	        		headers.insert("ipv4".to_string(), Value::Object(ipv4_header));
	        	},
	        	_ => (),
	        }
	        headers.insert("ethernet".to_string(), Value::Object(ethernet_header));
	        headers.insert("timestamp".to_string(), Value::Number(Number::from(timestamp)));

	headers
}

fn sniff(interface: &str, promiscuous: bool, snaplen: i32, timeout: i32) {
    let mut capture = Capture::from_device(interface).unwrap()
                      	.promisc(promiscuous)
                        .snaplen(snaplen)
                        .timeout(timeout)
                        .open()
                        .unwrap();

    while let Ok(packet) = capture.next() {
    	let packet_headers = parse_headers(packet);
		println!("{}", serde_json::to_string(&packet_headers).unwrap());
    }
    println!();
}

fn main() {
	const VERSION: &str = "0.1.0";
	const AUTHOR: &str = "Kevin Brebanov <kevin.brebanov@gmail.com>";
	const ABOUT: &str = "DNS packet sniffer that outputs to JSON";
	
    let arguments = App::new("snout")
                            .version(VERSION)
                            .author(AUTHOR)
                            .about(ABOUT)
                            .arg(Arg::with_name("interface")
                                .short("i")
                                .long("interface")
                                .value_name("INTERFACE")
                                .required(true)
                                .help("Network interface to sniff packets on")
                                .takes_value(true))
                            .arg(Arg::with_name("promiscuous")
                                .short("p")
                                .long("promiscuous")
                                .required(false)
                                .help("Enable promiscuous mode"))
                            .arg(Arg::with_name("snaplen")
                                .short("s")
                                .long("snaplen")
                                .value_name("SNAPLEN")
                                .required(false)
                                .help("Snapshot length")
                                .takes_value(true))
                            .arg(Arg::with_name("timeout")
                                .short("t")
                                .long("timeout")
                                .value_name("TIMEOUT")
                                .required(false)
                                .help("Read timeout in milliseconds")
                                .takes_value(true))
                            .get_matches();

    let interface = arguments.value_of("interface").unwrap();
    let mut promiscuous = false;
    if arguments.is_present("promiscuous") {
        promiscuous = true;
    }
    let snaplen: i32 = arguments.value_of("snaplen").unwrap_or("65535").parse().unwrap();
    let timeout: i32 = arguments.value_of("timeout").unwrap_or("0").parse().unwrap();

    sniff(interface, promiscuous, snaplen, timeout);
}
