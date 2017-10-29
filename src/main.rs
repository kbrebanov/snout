extern crate clap;
extern crate snout;

use clap::{App, Arg};
use snout::sniffer;
use std::process;

fn main() {
    const VERSION: &str = "0.3.0";
    const AUTHOR: &str = "Kevin Brebanov <kevin.brebanov@gmail.com>";
    const ABOUT: &str = "DNS packet sniffer that outputs to JSON";

    let arguments = App::new("snout")
        .version(VERSION)
        .author(AUTHOR)
        .about(ABOUT)
        .arg(
            Arg::with_name("interface")
                .short("i")
                .long("interface")
                .value_name("INTERFACE")
                .required(true)
                .help("Network interface to sniff packets on")
                .takes_value(true)
                .conflicts_with("list"),
        )
        .arg(
            Arg::with_name("promiscuous")
                .short("p")
                .long("promiscuous")
                .required(false)
                .help("Enable promiscuous mode")
                .conflicts_with("list"),
        )
        .arg(
            Arg::with_name("snaplen")
                .short("s")
                .long("snaplen")
                .value_name("SNAPLEN")
                .required(false)
                .help("Snapshot length")
                .takes_value(true)
                .conflicts_with("list"),
        )
        .arg(
            Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .value_name("TIMEOUT")
                .required(false)
                .help("Read timeout in milliseconds")
                .takes_value(true)
                .conflicts_with("list"),
        )
        .arg(
            Arg::with_name("filter")
                .short("f")
                .long("filter")
                .value_name("FILTER")
                .required(false)
                .help("Berkeley Packet Filter (BPF)")
                .takes_value(true)
                .conflicts_with("list"),
        )
        .arg(
            Arg::with_name("list")
                .short("l")
                .long("list")
                .value_name("LIST")
                .required(false)
                .help("List network interfaces")
                .takes_value(false),
        )
        .get_matches();

    if arguments.is_present("list") {
        match sniffer::list_interfaces() {
            Err(e) => {
                eprintln!("Error listing interfaces: {}", e);
                process::exit(1);
            }
            _ => (),
        }
        process::exit(0);
    }

    if let Some(interface) = arguments.value_of("interface") {
        let mut promiscuous = false;
        if arguments.is_present("promiscuous") {
            promiscuous = true;
        }
        let snaplen: i32 = match arguments.value_of("snaplen").unwrap_or("65535").parse() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error parsing snapshot length: {}", e);
                process::exit(1);
            }
        };
        let timeout: i32 = match arguments.value_of("timeout").unwrap_or("0").parse() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error parsing timeout: {}", e);
                process::exit(1);
            }
        };
        let filter: &str = arguments.value_of("filter").unwrap_or("");

        match sniffer::sniff(interface, promiscuous, snaplen, timeout, filter) {
            Err(e) => {
                eprintln!("Error sniffing packets: {}", e);
                process::exit(1);
            }
            _ => (),
        }

        process::exit(0);
    }
}
