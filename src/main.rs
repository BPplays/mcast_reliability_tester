use anyhow::{Context, Result};
use clap::Parser;
use pcap_parser::{create_reader, PcapBlockOwned, Block, PcapError};
use std::{fs::File, i64};
use std::io::BufReader;
use std::path::PathBuf;
use number_prefix::{NumberPrefix, Prefix};

#[derive(Parser, Debug)]
#[command(author, version, about = "Multicast RA Reliability Tester")]
struct Args {
    /// Pcap file from the router
    #[arg(short, long)]
    router_pcap: PathBuf,

    /// Pcap file from the device
    #[arg(short, long)]
    device_pcap: PathBuf,

    /// Margin in milliseconds around the start and end times to avoid miscounting
    #[arg(short, long, default_value = "1000")]
    margin: u64,
}

#[derive(Debug, Clone)]
struct RaPacket {
    timestamp_ns: u64,
}

fn prefix_name(prefix: Prefix) -> &'static str {
    match prefix {
        Prefix::Kilo => "kiloblocks",
        Prefix::Mega => "megablocks",
        Prefix::Giga => "gigablocks",
        Prefix::Tera => "terablocks",
        Prefix::Peta => "petablocks",
        Prefix::Exa => "exablocks",
        _ => "blocks",
    }
}

fn format_blocks(count: u64) -> String {
    match NumberPrefix::decimal(count as f64) {
        NumberPrefix::Standalone(n) => format!("{n:.0} blocks"),
        NumberPrefix::Prefixed(prefix, n) => {
            format!("{n:.2} {}", prefix_name(prefix))
        }
    }
}

fn get_ra_packets(path: &PathBuf) -> Result<Vec<RaPacket>> {
    let file = File::open(path).with_context(|| format!("Failed to open file {:?}", path))?;
    let buffered_reader = BufReader::new(file);
    let mut reader = create_reader(65536, buffered_reader)
        .with_context(|| format!("Failed to create reader for {:?}", path))?;

    let mut packets = Vec::new();
    let mut count = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                let mut skip = false;
                count += 1;
                if count % 10000000 == 0 {
                    println!("Reading {:?}... processed {}; offset: {}", path, format_blocks(count), offset);
                }

                let (data, ts_ns): (Option<&[u8]>, Option<u64>) = match block {
                    PcapBlockOwned::Legacy(legacy_block) => {
                        let ns = (legacy_block.ts_sec as u64 * 1_000_000_000) + (legacy_block.ts_usec as u64 * 1_000);
                        (Some(legacy_block.data), Some(ns))
                    }
                    PcapBlockOwned::NG(ng_block) => {

                        if let Block::EnhancedPacket(epb) = ng_block {
                            let ns = (epb.ts_high as u64 * 1_000_000_000) + (epb.ts_low as u64);
                            (Some(epb.data), Some(ns))
                        } else {
                            skip = true;
                            (None, None)
                        }
                    }
                    _ => {
                        skip = true;
                        (None, None)
                    },
                };


                if !skip && !data.is_none() && !ts_ns.is_none() {
                    let data = data.unwrap();
                    let ts_ns = ts_ns.unwrap();
                    if data.len() > 55 && data[12] == 0x86 && data[13] == 0xdd {
                        // Filter for destination IPv6 ff02::1 (All-Nodes Multicast)
                        // Destination address is at offset 14 (Eth) + 24 (IPv6) = 38
                        let dst_addr = &data[38..54];
                        let is_all_nodes = dst_addr[0] == 0xff
                                        && dst_addr[1] == 0x02
                                        && dst_addr[15] == 0x01
                                        && dst_addr[2..15].iter().all(|&b| b == 0);

                        if is_all_nodes && data[54] == 134 {
                            packets.push(RaPacket { timestamp_ns: ts_ns });
                        }
                    }
                }

                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("Finished reading {:?}: found {} RA packets", path, packets.len());
    Ok(packets)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let router_packets = get_ra_packets(&args.router_pcap)?;
    let device_packets = get_ra_packets(&args.device_pcap)?;

    if router_packets.is_empty() || device_packets.is_empty() {
        anyhow::bail!("No RA packets found in one or both files");
    }

    let router_start = router_packets.first().unwrap().timestamp_ns;
    let router_end = router_packets.last().unwrap().timestamp_ns;
    let device_start = device_packets.first().unwrap().timestamp_ns;
    let device_end = device_packets.last().unwrap().timestamp_ns;

    let latest_start = router_start.max(device_start);
    let earliest_end = router_end.min(device_end);

    let margin_ns = args.margin * 1_000_000;
    let start_window = latest_start + margin_ns;
    let end_window = earliest_end - margin_ns;

    if start_window >= end_window {
        anyhow::bail!("Time window is invalid or negative after applying margin");
    }

    let filtered_router: Vec<_> = router_packets.iter()
        .filter(|p| p.timestamp_ns >= start_window && p.timestamp_ns <= end_window)
        .collect();

    let filtered_device: Vec<_> = device_packets.iter()
        .filter(|p| p.timestamp_ns >= start_window && p.timestamp_ns <= end_window)
        .collect();

    println!("Analysis Window:");
    println!("  Start: {} ns", start_window);
    println!("  End:   {} ns", end_window);
    println!("  Duration: {} ms", (end_window - start_window) / 1_000_000);
    println!("------------------------------------------------------------");

    let total_sent = filtered_router.len();
    let match_threshold_ns = 1500_000_000_i64; // 10ms threshold for matching packets
    // let match_threshold_ns = i64::MAX; // 10ms threshold for matching packets


    let mut received_count = 0;
    let mut device_idx = 0;

    // O(N + M) Two-pointer matching algorithm
    for rp in &filtered_router {
        // Advance device pointer to the start of the potential match window
        while device_idx < filtered_device.len() &&
              (filtered_device[device_idx].timestamp_ns as i64 - rp.timestamp_ns as i64) < -(match_threshold_ns as i64) {
            device_idx += 1;
        }

        // Check if the current device packet matches the router packet
        if device_idx < filtered_device.len() &&
           (rp.timestamp_ns as i64 - filtered_device[device_idx].timestamp_ns as i64).abs() < match_threshold_ns as i64 {
            received_count += 1;
            device_idx += 1; // Consume this packet
        }
    }

    let dropped = total_sent - received_count;
    let reliability = if total_sent > 0 { (received_count as f64 / total_sent as f64) * 100.0 } else { 0.0 };

    println!("Results:");
    println!("  Total RAs Sent:     {}", total_sent);
    println!("  Total RAs Received: {}", received_count);
    println!("  Total Dropped:      {}", dropped);
    println!("  Reliability:        {:.2}%", reliability);
    println!("  Packet Loss Rate:   {:.2}%", 100.0 - reliability);

    Ok(())
}
