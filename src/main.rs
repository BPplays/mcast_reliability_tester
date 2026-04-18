use anyhow::{Context, Result};
use clap::Parser;
use etherparse::PacketHeaders;
use pcap::Capture;
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
    let mut cap = Capture::from_file(path).with_context(|| format!("Failed to open pcap {:?}", path))?;
    let mut packets = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        let ts = packet.header.ts;
        let timestamp_ns = (ts.tv_sec as u64 * 1_000_000_000) + (ts.tv_usec as u64 * 1_000);

        if let Ok(headers) = PacketHeaders::from_ethernet_slice(&packet.data) {
            if headers.net.is_some() {
                // The packet data usually includes the Ethernet header (14 bytes).
                // IPv6 header follows (40 bytes).
                // ICMPv6 Type is the first byte of the ICMPv6 header.
                // Total offset: 14 + 40 = 54.
                if packet.data.len() > 55 && packet.data[12] == 0x86 && packet.data[13] == 0xdd {
                    // Byte 12-13 is EtherType. 0x86dd is IPv6.
                    if packet.data[54] == 134 {
                        packets.push(RaPacket { timestamp_ns });
                    }
                }
            }
        }
    }
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
    println!("-------------------------------------------------");

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
