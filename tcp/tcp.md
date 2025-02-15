# Lesson 9 - TCP Summary

## Overview
This lesson provides an in-depth look at the **Transmission Control Protocol (TCP)**, focusing on its mechanisms for ensuring reliable communication, sequence numbers, acknowledgments, and the **three-way handshake** process. Hands-on exercises using **Wireshark** and discussions on **SYN flood attacks** are also included.

## Key Topics

### 1. Reliable Communication
- TCP ensures reliable delivery through:
  - **Sequence numbers**: Each byte in a transmission has a unique identifier.
  - **Acknowledgments (ACKs)**: The receiver confirms received data.
  - **Three-way handshake**: Establishes a reliable connection.

### 2. TCP vs. UDP
- **TCP**: Reliable, ensures packet order, error-checking.
- **UDP**: Best-effort delivery, no guaranteed order or reliability.

### 3. TCP Header Fields
- **Ports**: Source and destination.
- **Length**: Header + application data.
- **Checksum**: Detects errors, but does not correct them.

### 4. Sequence Numbers & Acknowledgments
- Each byte has a sequence number.
- **Next sequence number** = Current SEQ + Length.
- **ACK field** confirms receipt: `ACK 106` means "Received up to byte 105, expecting 106."

### 5. Connection Establishment: Three-Way Handshake
1. **SYN**: Client sends a request to connect (`SYN=1`).
2. **SYN-ACK**: Server acknowledges and sends back a `SYN-ACK` packet.
3. **ACK**: Client confirms receipt, communication starts.

### 6. Packet Loss & Retransmission
- **Stop-and-wait** method.
- **Go-Back-N** and **Selective Repeat** strategies.
- **Fast retransmit** on detecting missing packets.

### 7. TCP Congestion Control
- **Slow start** mechanism prevents overwhelming the network.
- Adjusts transmission rate based on network conditions.

### 8. Security Considerations: SYN Flood Attack
- **SYN flood attack**: Attacker sends multiple **SYN** packets without completing the handshake.
- Overloads server resources, leading to **Denial of Service (DoS)**.
- Further reading: [SYN Flood Attack](https://data.cyber.org.il/networks/SYN-Flood.pdf).

## Hands-on Exercises
- Using **Wireshark** to analyze TCP sequence numbers and ACKs.
- Simulating TCP handshake using **Scapy**.
- Observing and mitigating SYN flood attacks.

---

This presentation provides both **theoretical knowledge** and **practical insights** into how TCP functions in real-world networking.
