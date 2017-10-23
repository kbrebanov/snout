extern crate clap;
extern crate snout;

use clap::{Arg, App};
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
                            .arg(Arg::with_name("interface")
                                .short("i")
                                .long("interface")
                                .value_name("INTERFACE")
                                .required(true)
                                .help("Network interface to sniff packets on")
                                .takes_value(true)
                                .conflicts_with("list"))
                            .arg(Arg::with_name("promiscuous")
                                .short("p")
                                .long("promiscuous")
                                .required(false)
                                .help("Enable promiscuous mode")
                                .conflicts_with("list"))
                            .arg(Arg::with_name("snaplen")
                                .short("s")
                                .long("snaplen")
                                .value_name("SNAPLEN")
                                .required(false)
                                .help("Snapshot length")
                                .takes_value(true)
                                .conflicts_with("list"))
                            .arg(Arg::with_name("timeout")
                                .short("t")
                                .long("timeout")
                                .value_name("TIMEOUT")
                                .required(false)
                                .help("Read timeout in milliseconds")
                                .takes_value(true)
                                .conflicts_with("list"))
                            .arg(Arg::with_name("filter")
                                 .short("f")
                                 .long("filter")
                                 .value_name("FILTER")
                                 .required(false)
                                 .help("Berkeley Packet Filter (BPF)")
                                 .takes_value(true)
                                 .conflicts_with("list"))
                            .arg(Arg::with_name("list")
                                 .short("l")
                                 .long("list")
                                 .value_name("LIST")
                                 .required(false)
                                 .help("List network interfaces")
                                 .takes_value(false))
                            .get_matches();

    if arguments.is_present("list") {
        sniffer::list_interfaces();
        process::exit(0);
    }

    let interface = arguments.value_of("interface").unwrap();
    let mut promiscuous = false;
    if arguments.is_present("promiscuous") {
        promiscuous = true;
    }
    let snaplen: i32 = arguments.value_of("snaplen").unwrap_or("65535").parse().unwrap();
    let timeout: i32 = arguments.value_of("timeout").unwrap_or("0").parse().unwrap();
    let filter: &str = arguments.value_of("filter").unwrap_or("");

    sniffer::sniff(interface, promiscuous, snaplen, timeout, filter);

    process::exit(0);
}
