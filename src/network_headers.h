#ifndef NETWORK_HEADERS_H
#define NETWORK_HEADERS_H

#include <cstdint>
#include <arpa/inet.h>

#pragma pack(push, 1)

// Ethernet Header (14 bytes)
struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

// IP Header (20 bytes minimum)
struct IPHeader {
    uint8_t  hl:4,      // Header Length (in 32-bit words)
             v:4;       // Version (IPv4)
    uint8_t  tos;       // Type of Service
    uint16_t len;       // Total Length
    uint16_t id;        // Identification
    uint16_t off;       // Fragment Offset
    uint8_t  ttl;       // Time to Live
    uint8_t  p;         // Protocol (e.g., 6 for TCP)
    uint16_t sum;       // Checksum
    struct   in_addr ip_src, ip_dst; // Source and Destination Address
};

// TCP Header (20 bytes minimum)
struct TCPHeader {
    uint16_t sport;     // Source Port
    uint16_t dport;     // Destination Port
    uint32_t seq;       // Sequence Number
    uint32_t ack;       // Acknowledgement Number
    uint8_t  x2:4,      // Reserved
             off:4;     // Data Offset (Header Length in 32-bit words)
    uint8_t  flags;     // Control Flags (SYN, ACK, FIN, etc.)
    uint16_t win;       // Window
    uint16_t sum;       // Checksum
    uint16_t urp;       // Urgent Pointer
};

// TPKT Header (ISO-on-TCP) - 4 bytes
struct TPKTHeader {
    uint8_t version;
    uint8_t reserved;
    uint16_t length;
};

// COTP Header (Connection Oriented Transport Protocol) - 3 bytes for DT
struct COTPHeader {
    uint8_t length;
    uint8_t pdu_type;
    uint8_t last_data_unit; // For DT Data
};


#pragma pack(pop)

#endif // NETWORK_HEADERS_H
