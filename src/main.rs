use anyhow::{Context, Result};
use clap::Parser;
use pcap_parser::{create_reader, PcapBlockOwned, Block};
use std::fs::File;
use std::path::PathBuf;

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

fn get_ra_packets(path: &PathBuf) -> Result<Vec<RaPacket>> {
    let file = File::open(path).with_context(|| format!("Failed to open file {:?}", path))?;
    let mut reader = create_reader(65536, file)
        .with_context(|| format!("Failed to create reader for {:?}", path))?;

    let mut packets = Vec::new();

    loop {
        match reader.next() {
            Ok((_offset, block)) => {
                let (data, ts_ns) = match block {
                    PcapBlockOwned::Legacy(legacy_block) => {
                        let ns = (legacy_block.ts_sec as u64 * 1_000_000_000) + (legacy_block.ts_usec as u64 * 1_000);
                        (legacy_block.data, ns)
                    }
                    PcapBlockOwned::NG(ng_block) => {
                        if let Block::EnhancedPacket(epb) = ng_block {
                            let ns = (epb.ts_high as u64 * 1_000_000_000) + (epb.ts_low as u64);
                            (epb.data, ns)
                        } else {
                            continue;
                        }
                    }
                    _ => continue,
                };

                // The packet data usually includes the Ethernet header (14 bytes).
                // IPv6 header follows (40 bytes).
                // ICMPv6 Type is the first byte of the ICMPv6 header.
                // Total offset: 14 + 40 = 54.
                if data.len() > 55 && data[12] == 0x86 && data[13] == 0xdd {
                    if data[54] == 134 {
                       packets.push(RaPacket { timestamp_ns: ts_ns });
                    }
                }
            }
            Err(e) => {
                println!("error reading: {}", e);
                // break on EOF or errors
                break;
            }
        }
    }
    Ok(packets)
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("start get ra");
    let router_packets = get_ra_packets(&args.router_pcap)?;
    let device_packets = get_ra_packets(&args.device_pcap)?;
    println!("finished get ra");

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
    println!("-------------------------------------------------------");

    let total_sent = filtered_router.len();
    let mut received_count = 0;
    let match_threshold_ns = 10_000_000; // 10ms threshold for matching packets

    let mut device_used = vec![false; filtered_device.len()];

    for rp in &filtered_router {
        for (i, dp) in filtered_device.iter().enumerate() {
            if !device_used[i] && (rp.timestamp_ns as i64 - dp.timestamp_ns as i64).abs() < match_threshold_ns as i64 {
                received_count += 1;
                device_used[i] = true;
                break;
            }
        }
    }

    let dropped = total_sent - received_count;
    let reliability = (received_count as f64 / total_sent as f64) * 100.0;

    println!("Results:");
    println!("  Total RAs Sent:     {}", total_sent);
    println!("  Total RAs Received: {}", received_count);
    println!("  Total Dropped:      {}", dropped);
    println!("  Reliability:        {:.2}%", reliability);
    println!("  Packet Loss Rate:   {:.2}%", 100.0 - reliability);

    Ok(())
}
