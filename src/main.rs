extern crate clap;
extern crate pcap;

use clap::{Arg, App};
use pcap::Capture;

fn sniff(interface: &str, promiscuous: bool, snaplen: i32, timeout: i32) {
    let mut capture = pcap::Capture::from_device(interface).unwrap()
                                            .promisc(promiscuous)
                                            .snaplen(snaplen)
                                            .timeout(timeout)
                                            .open()
                                            .unwrap();

    while let Ok(packet) = capture.next() {
        println!("Timestamp: {}", packet.header.ts.tv_sec);
        println!("Data: {:?}", packet.data)
    }
}

fn main() {
    let arguments = clap::App::new("snout")
                                  .version("0.1.0")
                                  .author("Kevin Brebanov <kevin.brebanov@gmail.com>")
                                  .about("Packet sniffer")
                                  .arg(clap::Arg::with_name("interface")
                                      .short("i")
                                      .long("interface")
                                      .value_name("INTERFACE")
                                      .required(true)
                                      .help("Network interface to sniff packets on")
                                      .takes_value(true))
                                  .arg(clap::Arg::with_name("promiscuous")
                                      .short("p")
                                      .long("promiscuous")
                                      .required(false)
                                      .help("Enable promiscuous mode"))
                                  .arg(clap::Arg::with_name("snaplen")
                                      .short("s")
                                      .long("snaplen")
                                      .value_name("SNAPLEN")
                                      .required(false)
                                      .help("Snapshot length")
                                      .takes_value(true))
                                  .arg(clap::Arg::with_name("timeout")
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
    let timeout: i32 = arguments.value_of("timeout").unwrap_or("1000").parse().unwrap();

    sniff(interface, promiscuous, snaplen, timeout);
}
