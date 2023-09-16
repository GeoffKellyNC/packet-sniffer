extern crate pcap;

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

    loop {
        match cap.next() {
            Ok(packet) => {
                packet_count += 1;
                println!("========== Packet #{} ==========", packet_count);

                println!("Raw Packet: {:?}", packet);

                let packet_len = packet.data.len();

                if packet_len < 54 {
                    // Minimum length to read Ethernet, IP, and TCP headers
                    println!("Packet too small to process: {} bytes", packet_len);
                    continue;
                }

                // Ethernet header is usually 14 bytes
                let ethernet_header = &packet.data[0..14];

                // Source MAC address is 6 bytes starting at byte 6
                let src_mac = &ethernet_header[6..12];
                println!("Source MAC: {:?}", src_mac);

                // Destination MAC address is the first 6 bytes
                let dest_mac = &ethernet_header[0..6];
                println!("Destination MAC: {:?}", dest_mac);

                // IP header starts after Ethernet header
                let ip_header = &packet.data[14..34]; // Assuming no VLAN tags, etc.

                // Source IP is 4 bytes starting at byte 12
                let src_ip = &ip_header[12..16];
                println!("Source IP: {:?}", src_ip);

                // Destination IP is 4 bytes starting at byte 16
                let dest_ip = &ip_header[16..20];
                println!("Destination IP: {:?}", dest_ip);

                // Assuming Ethernet header is 14 bytes
                let ethernet_header_end = 14;

                // Assuming IP header is 20 bytes (can vary)
                let ip_header_end = ethernet_header_end + 20;

                // Assuming TCP header is 20 bytes (can vary)
                let tcp_header_end = ip_header_end + 20;

                // Extract TCP source and destination ports
                let tcp_src_port = u16::from_be_bytes([
                    packet.data[ip_header_end],
                    packet.data[ip_header_end + 1],
                ]);
                let tcp_dest_port = u16::from_be_bytes([
                    packet.data[ip_header_end + 2],
                    packet.data[ip_header_end + 3],
                ]);

                println!("Source Port: {}", tcp_src_port);
                println!("Destination Port: {}", tcp_dest_port);

                match tcp_dest_port {
                    80 => println!("Likely HTTP data"),
                    443 => println!("Likely HTTPS data"),
                    21 => println!("Likely FTP data"),
                    22 => println!("Likely SSH data"),
                    _ => println!("Unknown data type"),
                }

                // Extract application data
                let app_data = &packet.data[tcp_header_end..];

                // Try to interpret as a UTF-8 string
                if let Ok(text) = std::str::from_utf8(app_data) {
                    // Check if it looks like HTTP data
                    if text.starts_with("GET")
                        || text.starts_with("POST")
                        || text.starts_with("HTTP")
                    {
                        println!("HTTP data: {}", text);
                    } else {
                        println!("Non-HTTP data: {:?}", app_data);
                    }
                } else {
                    println!("Non-textual data: {:?}", app_data);
                }

                println!("=================================\n");
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("An error occurred: {:?}", e);
                break;
            }
        }
    }
}
