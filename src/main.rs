mod dns_packet;
use std::net::UdpSocket;
use std::error::Error;

use crate::dns_packet::{PacketBuffer, Packet, Record};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

// Rest of the code...

fn main() -> Result<()> {
    // Create a UDP socket and bind it to port 53 (default DNS port)
    let socket = UdpSocket::bind("0.0.0.0:53")?;
    println!("DNS server listening on port 53...");

    // Create a buffer to store the received packet
    let mut buffer = [0; 512];

    loop {
        // Receive a DNS packet from a client
        let (size, _) = socket.recv_from(&mut buffer)?;

        // Create a PacketBuffer from the received data
        let mut packet_buffer = PacketBuffer::new();
        packet_buffer.buf[..size].copy_from_slice(&buffer[..size]);

        // Create a Packet instance and populate it from the buffer
        let packet_result = Packet::from_buffer(&mut packet_buffer);
        if let Err(err) = packet_result {
            println!("Failed to parse DNS packet: {}", err);
            continue;
        }
        let packet = packet_result.unwrap();

        // Print the DNS packet details
        println!("--- Received DNS Packet ---");
        println!("Header: {:?}", packet.header);
        println!("Questions:");
        for question in &packet.questions {
            println!("  Name: {}", question.name);
            println!("  Record Type: {:?}", question.record);
        }
        println!("Answers:");
        for answer in &packet.answers {
            match answer {
                Record::A { domain, addr, ttl } => {
                    println!("  Domain: {}", domain);
                    println!("  Address (A): {}", addr);
                    println!("  TTL: {}", ttl);
                }
                Record::AAAA { domain, addr, ttl } => {
                    println!("  Domain: {}", domain);
                    println!("  Address (AAAA): {}", addr);
                    println!("  TTL: {}", ttl);
                }
            }
        }
        println!("Authorities: {:?}", packet.authorities);
        println!("Additionals: {:?}", packet.additionals);
    }
}
