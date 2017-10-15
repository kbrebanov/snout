extern crate clap;
extern crate pcap;
extern crate pnet;
extern crate serde_json;

use clap::{Arg, App};
use pcap::Capture;
use pnet::packet::{Packet, ethernet, ip, ipv4, tcp, udp};
use serde_json::{Value, Map, Number};

fn sniff(interface: &str, promiscuous: bool, snaplen: i32, timeout: i32) {
    let mut capture = Capture::from_device(interface).unwrap()
                      	.promisc(promiscuous)
                        .snaplen(snaplen)
                        .timeout(timeout)
                        .open()
                        .unwrap();

    while let Ok(packet) = capture.next() {
    	let mut packet_headers = Map::new();
    	
        let timestamp = packet.header.ts.tv_sec;
        
        let ethernet_packet = ethernet::EthernetPacket::new(packet.data).unwrap();
        let ethernet_source = ethernet_packet.get_source();
        let ethernet_destination = ethernet_packet.get_destination();
        let ethernet_type = ethernet_packet.get_ethertype();
        
		let mut ethernet_header = Map::new();
		ethernet_header.insert("source".to_string(), Value::String(ethernet_source.to_string()));
		ethernet_header.insert("destination".to_string(), Value::String(ethernet_destination.to_string()));
		ethernet_header.insert("type".to_string(), Value::String(ethernet_type.to_string()));

        match ethernet_type {
        	ethernet::EtherTypes::Ipv4 => {
        		let ipv4_packet = ipv4::Ipv4Packet::new(ethernet_packet.payload()).unwrap();
        		let ipv4_version = ipv4_packet.get_version();
        		let ipv4_ihl = ipv4_packet.get_header_length();
        		let ipv4_dscp = ipv4_packet.get_dscp();
        		let ipv4_ecn = ipv4_packet.get_ecn();
        		let ipv4_total_length = ipv4_packet.get_total_length();
        		let ipv4_identification = ipv4_packet.get_identification();
        		let ipv4_flags = ipv4_packet.get_flags();
        		let ipv4_fragment_offset = ipv4_packet.get_fragment_offset();
				let ipv4_ttl = ipv4_packet.get_ttl();
        		let ipv4_next_level_protocol = ipv4_packet.get_next_level_protocol();
        		let ipv4_checksum = ipv4_packet.get_checksum(); 
        		let ipv4_source = ipv4_packet.get_source();
        		let ipv4_destination = ipv4_packet.get_destination();
        		
        		let mut ipv4_header = Map::new();
        		ipv4_header.insert("version".to_string(), Value::Number(Number::from(ipv4_version)));
        		ipv4_header.insert("ihl".to_string(), Value::Number(Number::from(ipv4_ihl)));
        		ipv4_header.insert("dscp".to_string(), Value::Number(Number::from(ipv4_dscp)));
        		ipv4_header.insert("ecn".to_string(), Value::Number(Number::from(ipv4_ecn)));
        		ipv4_header.insert("total_length".to_string(), Value::Number(Number::from(ipv4_total_length)));
        		ipv4_header.insert("identification".to_string(), Value::Number(Number::from(ipv4_identification)));
        		ipv4_header.insert("flags.".to_string(), Value::Number(Number::from(ipv4_flags)));
        		ipv4_header.insert("fragment_offset".to_string(), Value::Number(Number::from(ipv4_fragment_offset)));
        		ipv4_header.insert("ttl".to_string(), Value::Number(Number::from(ipv4_ttl)));
        		ipv4_header.insert("protocol".to_string(), Value::String(ipv4_next_level_protocol.to_string().to_lowercase()));
        		ipv4_header.insert("checksum".to_string(), Value::Number(Number::from(ipv4_checksum)));
        		ipv4_header.insert("source_address".to_string(), Value::String(ipv4_source.to_string()));
        		ipv4_header.insert("destination_address".to_string(), Value::String(ipv4_destination.to_string()));
        
        		match ipv4_next_level_protocol {
        			ip::IpNextHeaderProtocols::Tcp => {
        				let tcp_packet = tcp::TcpPacket::new(ipv4_packet.payload()).unwrap();
        				let tcp_source_port = tcp_packet.get_source();
        				let tcp_destination_port = tcp_packet.get_destination();
        				let tcp_sequence_number = tcp_packet.get_sequence();
        				let tcp_ack_number = tcp_packet.get_acknowledgement();
        				let tcp_data_offset = tcp_packet.get_data_offset();
        				let tcp_flags = tcp_packet.get_flags();
        				let tcp_window_size = tcp_packet.get_window();
        				let tcp_checksum = tcp_packet.get_checksum();
        				let tcp_urgent_pointer = tcp_packet.get_urgent_ptr();
        				
        				let mut tcp_header = Map::new();
        				tcp_header.insert("source_port".to_string(), Value::String(tcp_source_port.to_string()));
        				tcp_header.insert("destination_port".to_string(), Value::String(tcp_destination_port.to_string()));
        				tcp_header.insert("sequence_number".to_string(), Value::Number(Number::from(tcp_sequence_number)));
        				tcp_header.insert("ack_number".to_string(), Value::Number(Number::from(tcp_ack_number)));
        				tcp_header.insert("data_offset".to_string(), Value::Number(Number::from(tcp_data_offset)));
        				tcp_header.insert("flags".to_string(), Value::Number(Number::from(tcp_flags)));
        				tcp_header.insert("window_size".to_string(), Value::Number(Number::from(tcp_window_size)));
        				tcp_header.insert("checksum".to_string(), Value::Number(Number::from(tcp_checksum)));
        				tcp_header.insert("urgent_pointer".to_string(), Value::Number(Number::from(tcp_urgent_pointer)));

        				packet_headers.insert("tcp".to_string(), Value::Object(tcp_header));
        			},
        			ip::IpNextHeaderProtocols::Udp => {
        				let udp_packet = udp::UdpPacket::new(ipv4_packet.payload()).unwrap();
        				let udp_source_port = udp_packet.get_source();
        				let udp_destination_port = udp_packet.get_destination();
        				let udp_length = udp_packet.get_length();
        				let udp_checksum = udp_packet.get_checksum();
        				
        				let mut udp_header = Map::new();
        				udp_header.insert("source_port".to_string(), Value::String(udp_source_port.to_string()));
        				udp_header.insert("destination_port".to_string(), Value::String(udp_destination_port.to_string()));
        				udp_header.insert("length".to_string(), Value::Number(Number::from(udp_length)));
        				udp_header.insert("checksum".to_string(), Value::Number(Number::from(udp_checksum)));

        				packet_headers.insert("udp".to_string(), Value::Object(udp_header));
        			},
        			_ => (),
        		}
        		packet_headers.insert("ipv4".to_string(), Value::Object(ipv4_header));
        	},
        	_ => (),
        }
        packet_headers.insert("ethernet".to_string(), Value::Object(ethernet_header));
        packet_headers.insert("timestamp".to_string(), Value::Number(Number::from(timestamp)));
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
