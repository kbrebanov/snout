use pcap;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use dns_parser::Packet as DnsPacket;
use serde_json::{Value, Map, Number};

mod ethernet;
mod ipv4;
mod tcp;
mod udp;
mod dns;

pub fn parse_headers(p: pcap::Packet) -> Map<String, Value> {
	let mut headers = Map::new();
	    	
	let timestamp = p.header.ts.tv_sec;
	        
	let ethernet_packet = EthernetPacket::new(p.data).unwrap();
	let ethernet_header = ethernet::EthernetHeader::new(&ethernet_packet).to_json_map();
	        
	match ethernet_packet.get_ethertype() {
	    EtherTypes::Ipv4 => {
	        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
			let ipv4_header = ipv4::Ipv4Header::new(&ipv4_packet).to_json_map();
	        		
	        match ipv4_packet.get_next_level_protocol() {
	        	IpNextHeaderProtocols::Tcp => {
	        		let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
	        		let tcp_header = tcp::TcpHeader::new(&tcp_packet).to_json_map();
	        		headers.insert("tcp".to_string(), Value::Object(tcp_header));

					if let Ok(dns_packet) = DnsPacket::parse(tcp_packet.payload()) {
						let dns_header = dns::DnsHeader::new(&dns_packet).to_json_map();
	        			headers.insert("dns".to_string(), Value::Object(dns_header));
					}
	        	},
	        	IpNextHeaderProtocols::Udp => {
	        		let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
	        		let udp_header = udp::UdpHeader::new(&udp_packet).to_json_map();
	        		headers.insert("udp".to_string(), Value::Object(udp_header));

					if let Ok(dns_packet) = DnsPacket::parse(udp_packet.payload()) {
						let dns_header = dns::DnsHeader::new(&dns_packet).to_json_map();
	        			headers.insert("dns".to_string(), Value::Object(dns_header));
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