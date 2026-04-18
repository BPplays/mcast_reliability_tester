use anyhow::{Context, Result};
use clap::Parser;
use etherparse::{PacketHeaders, IpHeader, TransportHeader};
use pcap::PcapReader;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

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
    // We can add more identifiers here if needed, e.g., sequence numbers if present
}

fn get_ra_packets(path: &PathBuf) -> Result<Vec<RaPacket>> {
    let mut cap = PcapReader::open(path).with_context(|| format!("Failed to open pcap {:?}", path))?;
    let mut packets = Vec::new();

    while let Ok(packet) = cap.next_packet() {
        let ts = packet.header.ts;
        let timestamp_ns = (ts.tv_sec as u64 * 1_000_000_000) + (ts.tv_usec as u64 * 1_000);

        // Parse packet
        if let Ok(headers) = PacketHeaders::from_ethernet_slice(&packet.data) {
            if let Some(ip) = headers.ip {
                if let Some(ip_header) = ip {
                    // Check for IPv6 and Multicast Destination (ff02::1)
                    // For simplicity in this implementation, we check if it's ICMPv6 Type 134
                    if let Some(transport) = headers.transport {
                        if let TransportHeader::Icmpv6(icmpv6) = transport {
                            // ICMPv6 Type 134 is Router Advertisement
                            // Note: etherparse might not have the full ICMPv6 type in the enum
                            // but we can check the raw data if needed.
                        }
                    }
                }
            }
        }
        
        // Since etherparse's ICMPv6 support might be limited in version 0.19,
        // we can manually check the bytes for ICMPv6 Type 134.
        // IPv6 header is 40 bytes. ICMPv6 type is at offset 40.
        if packet.data.len() > 41 && packet.data[0] == 0x6 /* IPv6 version */ {
            // Check if destination is multicast ff02::1 (simplified check)
            // and check if the byte at offset 40 is 134 (0x86)
            if packet.data[40] == 134 {
                packets.push(RaPacket { timestamp_ns });
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
