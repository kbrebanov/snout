extern crate clap;
extern crate pcap;
extern crate pnet;
extern crate serde_json;
extern crate dns_parser;

use clap::{Arg, App};
use pcap::Capture;
use pnet::packet::{Packet, ethernet, ip, ipv4, tcp, udp};
use serde_json::{Value, Map, Number};
use dns_parser::Packet as DnsPacket;

struct EthernetHeader {
	source: String,
	destination: String,
	ethertype: String,
}

struct Ipv4Header {
	version: Number,
	ihl: Number,
	dscp: Number,
	ecn: Number,
	total_length: Number,
	identification: Number,
	flags: Number,
	fragment_offset: Number,
	ttl: Number,
	next_level_protocol: String,
	checksum: Number,
	source: String,
	destination: String,
}

struct TcpHeader {
	source_port: Number,
	destination_port: Number,
	sequence_number: Number,
	ack_number: Number,
	data_offset: Number,
	flags: Number,
	window_size: Number,
	checksum: Number,
	urgent_pointer: Number,
}

struct UdpHeader {
	source_port: Number,
	destination_port: Number,
	length: Number,
	checksum: Number,
}

struct DnsHeader {
	id: Number,
	total_questions: Number,
	total_answer_rrs: Number,
	total_authority_rrs: Number,
	total_additional_rrs: Number,
}

fn parse_ethernet(p: &ethernet::EthernetPacket) -> Map<String, Value> {
    let ethernet_header = EthernetHeader {
		source: p.get_source().to_string(),
		destination: p.get_destination().to_string(),
		ethertype: p.get_ethertype().to_string().to_lowercase(), 	
    };

	let mut header = Map::new();
	header.insert("source".to_string(), Value::String(ethernet_header.source));
	header.insert("destination".to_string(), Value::String(ethernet_header.destination));
	header.insert("type".to_string(), Value::String(ethernet_header.ethertype));

	header
}

fn parse_ipv4(p: &ipv4::Ipv4Packet) -> Map<String, Value> {
	let ipv4_header = Ipv4Header {
		version: Number::from(p.get_version()),
		ihl: Number::from(p.get_header_length()),
		dscp: Number::from(p.get_dscp()),
		ecn: Number::from(p.get_ecn()),
		total_length: Number::from(p.get_total_length()),
		identification: Number::from(p.get_identification()),
		flags: Number::from(p.get_flags()),
		fragment_offset: Number::from(p.get_fragment_offset()),
		ttl: Number::from(p.get_ttl()),
		next_level_protocol: p.get_next_level_protocol().to_string().to_lowercase(),
		checksum: Number::from(p.get_checksum()),
		source: p.get_source().to_string(),
		destination: p.get_destination().to_string(),
	};

	let mut header = Map::new();
    header.insert("version".to_string(), Value::Number(ipv4_header.version));
    header.insert("ihl".to_string(), Value::Number(ipv4_header.ihl));
    header.insert("dscp".to_string(), Value::Number(ipv4_header.dscp));
    header.insert("ecn".to_string(), Value::Number(ipv4_header.ecn));
    header.insert("total_length".to_string(), Value::Number(ipv4_header.total_length));
    header.insert("identification".to_string(), Value::Number(ipv4_header.identification));
    header.insert("flags.".to_string(), Value::Number(ipv4_header.flags));
    header.insert("fragment_offset".to_string(), Value::Number(ipv4_header.fragment_offset));
    header.insert("ttl".to_string(), Value::Number(ipv4_header.ttl));
    header.insert("protocol".to_string(), Value::String(ipv4_header.next_level_protocol));
    header.insert("checksum".to_string(), Value::Number(ipv4_header.checksum));
    header.insert("source_address".to_string(), Value::String(ipv4_header.source));
    header.insert("destination_address".to_string(), Value::String(ipv4_header.destination));
    
	header
}

fn parse_tcp(p: &tcp::TcpPacket) -> Map<String, Value> {
	let tcp_header = TcpHeader {
		source_port: Number::from(p.get_source()),
		destination_port: Number::from(p.get_destination()),
		sequence_number: Number::from(p.get_sequence()),
		ack_number: Number::from(p.get_acknowledgement()),
		data_offset: Number::from(p.get_data_offset()),
		flags: Number::from(p.get_flags()),
		window_size: Number::from(p.get_window()),
		checksum: Number::from(p.get_checksum()),
		urgent_pointer: Number::from(p.get_urgent_ptr()),
	};

	let mut header = Map::new();
	header.insert("source_port".to_string(), Value::Number(tcp_header.source_port));
	header.insert("destination_port".to_string(), Value::Number(tcp_header.destination_port));
	header.insert("sequence_number".to_string(), Value::Number(tcp_header.sequence_number));
	header.insert("ack_number".to_string(), Value::Number(tcp_header.ack_number));
	header.insert("data_offset".to_string(), Value::Number(tcp_header.data_offset));
	header.insert("flags".to_string(), Value::Number(tcp_header.flags));
	header.insert("window_size".to_string(), Value::Number(tcp_header.window_size));
	header.insert("checksum".to_string(), Value::Number(tcp_header.checksum));
	header.insert("urgent_pointer".to_string(), Value::Number(tcp_header.urgent_pointer));

	header
}

fn parse_udp(p: &udp::UdpPacket) -> Map<String, Value> {
	let udp_header = UdpHeader {
		source_port: Number::from(p.get_source()),
		destination_port: Number::from(p.get_destination()),
		length: Number::from(p.get_length()),
		checksum: Number::from(p.get_checksum()),		
	};
	        				
	let mut header = Map::new();
	header.insert("source_port".to_string(), Value::Number(udp_header.source_port));
	header.insert("destination_port".to_string(), Value::Number(udp_header.destination_port));
	header.insert("length".to_string(), Value::Number(udp_header.length));
	header.insert("checksum".to_string(), Value::Number(udp_header.checksum));

	header
}

fn parse_dns(p: &DnsPacket) -> Map<String, Value> {
	let dns_header = DnsHeader {
		id: Number::from(p.header.id),
		total_questions: Number::from(p.header.questions),
		total_answer_rrs: Number::from(p.header.answers),
		total_authority_rrs: Number::from(p.header.nameservers),
		total_additional_rrs: Number::from(p.header.additional),		
	};	

	let mut header = Map::new();
	header.insert("id".to_string(), Value::Number(dns_header.id));
	header.insert("total_questions".to_string(), Value::Number(dns_header.total_questions));
	header.insert("total_answer_rrs".to_string(), Value::Number(dns_header.total_answer_rrs));
	header.insert("total_authority_rrs".to_string(), Value::Number(dns_header.total_authority_rrs));
	header.insert("total_additional_rrs".to_string(), Value::Number(dns_header.total_additional_rrs));

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

	        				match DnsPacket::parse(tcp_packet.payload()) {
	        					Ok(dns_packet) => {
	        						let dns_header = parse_dns(&dns_packet);
	        					    headers.insert("dns".to_string(), Value::Object(dns_header));
	        					},
	        					Err(_) => (),
	        				}
	        			},
	        			ip::IpNextHeaderProtocols::Udp => {
	        				let udp_packet = udp::UdpPacket::new(ipv4_packet.payload()).unwrap();
	        				let udp_header = parse_udp(&udp_packet);
	        				headers.insert("udp".to_string(), Value::Object(udp_header));

	        				match DnsPacket::parse(udp_packet.payload()) {
	        					Ok(dns_packet) => {
	        						let dns_header = parse_dns(&dns_packet);
	        						headers.insert("dns".to_string(), Value::Object(dns_header));
	        					},
	        					Err(_) => (),
	        				}
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

fn sniff(interface: &str, promiscuous: bool, snaplen: i32, timeout: i32, filter: &str) {
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
                            .arg(Arg::with_name("filter")
                                 .short("f")
                                 .long("filter")
                                 .value_name("FILTER")
                                 .required(false)
                                 .help("Berkeley Packet Filter (BPF)")
                                 .takes_value(true))
                            .get_matches();

    let interface = arguments.value_of("interface").unwrap();
    let mut promiscuous = false;
    if arguments.is_present("promiscuous") {
        promiscuous = true;
    }
    let snaplen: i32 = arguments.value_of("snaplen").unwrap_or("65535").parse().unwrap();
    let timeout: i32 = arguments.value_of("timeout").unwrap_or("0").parse().unwrap();
    let filter: &str = arguments.value_of("filter").unwrap_or("");

    sniff(interface, promiscuous, snaplen, timeout, filter);
}
