extern crate colored;
extern crate ndarray;
extern crate ndarray_stats;
extern crate pcap;

use chrono::prelude::*;
use colored::*;
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::thread;
use std::time::Duration;

fn main() {
    let device = pcap::Device::lookup().expect("Failed to lookup device");
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .immediate_mode(true)
        .open()
        .unwrap();

    let mut packet_count = 0;
    let mut good_count = 0;
    let mut failed_login_count = 0;
    let mut unusual_traffic_count = 0;
    let mut unusual_time_count = 0;
    let mut risky_ip_count = 0;
    let mut unusual_port_count = 0;

    let mut failed_login_ips: HashMap<String, i32> = HashMap::new();
    let mut bytes: Vec<f64> = Vec::new();

    loop {
        // Slow down the output
        thread::sleep(Duration::from_millis(500));

        match cap.next() {
            Ok(packet) => {
                packet_count += 1;
                let packet_len = packet.data.len() as f64;
                bytes.push(packet_len);

                if packet_len < 54.0 {
                    // Minimum length to read Ethernet, IP, and TCP headers
                    println!("Packet too small to process: {} bytes", packet_len);
                    continue;
                }

                let mut is_suspicious = false;
                let mut reason = String::new();

                let ethernet_header = &packet.data[0..14];
                let src_mac = &ethernet_header[6..12];
                let dest_mac = &ethernet_header[0..6];
                let ip_header = &packet.data[14..34];
                let src_ip = &ip_header[12..16];
                let dest_ip = &ip_header[16..20];
                let ethernet_header_end = 14;
                let ip_header_end = ethernet_header_end + 20;
                let tcp_header_end = ip_header_end + 20;
                let tcp_src_port = u16::from_be_bytes([
                    packet.data[ip_header_end],
                    packet.data[ip_header_end + 1],
                ]);
                let tcp_dest_port = u16::from_be_bytes([
                    packet.data[ip_header_end + 2],
                    packet.data[ip_header_end + 3],
                ]);
                let app_data = &packet.data[tcp_header_end..];
                let text = std::str::from_utf8(app_data).unwrap_or("");

                // 1. Unusual Traffic Patterns
                let bytes_array = Array1::from(bytes.clone());
                let mean = bytes_array.mean().unwrap();
                let std_dev = bytes_array.std(0.0);
                let threshold = mean + 2.0 * std_dev;
                if packet_len > threshold {
                    is_suspicious = true;
                    reason = "Unusual Traffic Patterns".to_string();
                    println!("========== {} #{} ==========", reason.blue(), packet_count);
                    println!("Details:");
                    println!("  - Mean Packet Size: {:.2}", mean);
                    println!("  - Standard Deviation: {:.2}", std_dev);
                    println!("  - Threshold: {:.2}", threshold);
                    println!("  - Current Packet Size: {:.2}", packet_len);
                    println!(
                        "  - Packet exceeds the threshold by {:.2}",
                        packet_len - threshold
                    );
                }

                // 2. Multiple Failed Logins
                if text.contains("Failed Login") {
                    let src_ip_str = format!("{:?}", src_ip);
                    let counter = failed_login_ips.entry(src_ip_str).or_insert(0);
                    *counter += 1;
                    if *counter > 5 {
                        is_suspicious = true;
                        reason = "Multiple Failed Logins".to_string();
                        println!(
                            "========== {} #{} ==========",
                            reason.yellow(),
                            packet_count
                        );
                    }
                }

                // 3. Unusual Times of Activity
                let local_time = Local::now();
                let current_hour = local_time.hour() as i32;

                if (0..=6).contains(&current_hour) {
                    is_suspicious = true;
                    reason = "Unusual Times of Activity".to_string();
                    println!(
                        "========== {} #{} ==========",
                        reason.magenta(),
                        packet_count
                    );
                    println!("Current Hour: {}", current_hour);
                }

                // 4. Connections to Risky IPs

                // Getting Risky IP's from Text File
                let mut risky_ips: Vec<String> = Vec::new(); // Placeholder
                let path = Path::new("src/risky_ips.txt");
                let file = File::open(path).expect("Failed to Open Risky IP File");
                let reader = io::BufReader::new(file);

                for line in reader.lines() {
                    let ip = line.expect("Could Not read Line");
                    risky_ips.push(ip)
                }

                let dest_ip_str = format!("{:?}", dest_ip);
                if risky_ips.contains(&dest_ip_str) {
                    is_suspicious = true;
                    reason = "Connections to Risky IPs".to_string();
                    println!("========== {} #{} ==========", reason.red(), packet_count);
                }

                // 5. Unusual Protocols or Ports
                if tcp_dest_port > 1024 {
                    is_suspicious = true;
                    reason = "Unusual Protocols or Ports".to_string();
                    println!("========== {} #{} ==========", reason.green(), packet_count);
                }

                if is_suspicious {
                    match reason.as_str() {
                        "Unusual Traffic Patterns" => unusual_traffic_count += 1,
                        "Multiple Failed Logins" => failed_login_count += 1,
                        "Unusual Times of Activity" => unusual_time_count += 1,
                        "Connections to Risky IPs" => risky_ip_count += 1,
                        "Unusual Protocols or Ports" => unusual_port_count += 1,
                        _ => {}
                    }

                    println!("Source MAC: {:?}", src_mac);
                    println!("Destination MAC: {:?}", dest_mac);
                    println!("Source IP: {:?}", src_ip);
                    println!("Destination IP: {:?}", dest_ip);
                    println!("Source Port: {}", tcp_src_port);
                    println!("Destination Port: {}", tcp_dest_port);
                    println!("Packet Data: {:?}", packet.data);
                    println!("=================================\n");
                } else {
                    good_count += 1;
                }

                println!("Total Packets: {}", packet_count);
                println!("Good Packets: {}", good_count.to_string().green());
                println!(
                    "Unusual Traffic: {}",
                    unusual_traffic_count.to_string().blue()
                );
                println!("Failed Logins: {}", failed_login_count.to_string().yellow());
                println!(
                    "Unusual Times: {}",
                    unusual_time_count.to_string().magenta()
                );
                println!("Risky IPs: {}", risky_ip_count.to_string().red());
                println!("Unusual Ports: {}", unusual_port_count.to_string().green());
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("An error occurred: {:?}", e);
                break;
            }
        }
    }
}
