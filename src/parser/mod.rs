use dns_parser::Packet as DnsPacket;
use pcap;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use serde_json::{Map, Value, to_value};
use serde_json::error::Error;

mod ethernet;
mod ipv4;
mod ipv6;
mod tcp;
mod udp;
mod dns;

pub fn parse_headers(p: pcap::Packet) -> Result<Map<String, Value>, Error> {
    let mut headers = Map::new();

    let timestamp = p.header.ts.tv_sec;

    if let Some(ethernet_packet) = EthernetPacket::new(p.data) {
        let ethernet_header = ethernet::EthernetHeader::new(&ethernet_packet).to_json_map()?;

        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                    let ipv4_header = ipv4::Ipv4Header::new(&ipv4_packet).to_json_map()?;

                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                let tcp_header = tcp::TcpHeader::new(&tcp_packet).to_json_map()?;
                                headers.insert(String::from("tcp"), to_value(tcp_header)?);

                                if let Ok(dns_packet) = DnsPacket::parse(tcp_packet.payload()) {
                                    let dns_header = dns::DnsHeader::new(&dns_packet).to_json_map()?;
                                    headers.insert(String::from("dns"), to_value(dns_header)?);
                                }
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                                let udp_header = udp::UdpHeader::new(&udp_packet).to_json_map()?;
                                headers.insert(String::from("udp"), to_value(udp_header)?);

                                if let Ok(dns_packet) = DnsPacket::parse(udp_packet.payload()) {
                                    let dns_header = dns::DnsHeader::new(&dns_packet).to_json_map()?;
                                    headers.insert(String::from("dns"), to_value(dns_header)?);
                                }
                            }
                        }
                        _ => (),
                    }
                    headers.insert(String::from("ipv4"), to_value(ipv4_header)?);
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                    let ipv6_header = ipv6::Ipv6Header::new(&ipv6_packet).to_json_map()?;

                    match ipv6_packet.get_next_header() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                                let tcp_header = tcp::TcpHeader::new(&tcp_packet).to_json_map()?;
                                headers.insert(String::from("tcp"), to_value(tcp_header)?);

                                if let Ok(dns_packet) = DnsPacket::parse(tcp_packet.payload()) {
                                    let dns_header = dns::DnsHeader::new(&dns_packet).to_json_map()?;
                                    headers.insert(String::from("dns"), to_value(dns_header)?);
                                }
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp_packet) = UdpPacket::new(ipv6_packet.payload()) {
                                let udp_header = udp::UdpHeader::new(&udp_packet).to_json_map()?;
                                headers.insert(String::from("udp"), to_value(udp_header)?);

                                if let Ok(dns_packet) = DnsPacket::parse(udp_packet.payload()) {
                                    let dns_header = dns::DnsHeader::new(&dns_packet).to_json_map()?;
                                    headers.insert(String::from("dns"), to_value(dns_header)?);
                                }
                            }
                        }
                        _ => (),
                    }
                    headers.insert(String::from("ipv6"), to_value(ipv6_header)?);
                }
            }
            _ => (),
        }
        headers.insert(String::from("ethernet"), to_value(ethernet_header)?);
        headers.insert(
            String::from("timestamp"),
            to_value(timestamp)?,
        );
    }

    Ok(headers)
}
