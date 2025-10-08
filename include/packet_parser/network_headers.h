#ifndef NETWORK_HEADERS_H
#define NETWORK_HEADERS_H

#include <cstdint>
#include <arpa/inet.h>

// 컴파일러의 자동 패딩 방지
#pragma pack(push, 1)

// Ethernet Header (14 bytes)
struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
};

// IP Header (20 bytes minimum)
struct IPHeader {
    uint8_t  ip_hl:4,      // Header Length (in 32-bit words)
             ip_v:4;       // Version (IPv4)
    uint8_t  ip_tos;       // Type of Service
    uint16_t ip_len;       // Total Length
    uint16_t ip_id;        // Identification
    uint16_t ip_off;       // Fragment Offset
    uint8_t  ip_ttl;       // Time to Live
    uint8_t  ip_p;         // Protocol (e.g., 6 for TCP)
    uint16_t ip_sum;       // Checksum
    struct   in_addr ip_src, ip_dst; // Source and Destination Address
};

// TCP Header (20 bytes minimum)
struct TCPHeader {
    uint16_t th_sport;     // Source Port
    uint16_t th_dport;     // Destination Port
    uint32_t th_seq;       // Sequence Number
    uint32_t th_ack;       // Acknowledgement Number
    uint8_t  th_x2:4,      // Reserved
             th_off:4;     // Data Offset (Header Length in 32-bit words)
    uint8_t  th_flags;     // Control Flags (SYN, ACK, FIN, etc.)
    uint16_t th_win;       // Window
    uint16_t th_sum;       // Checksum
    uint16_t th_urp;       // Urgent Pointer
};

#pragma pack(pop)

#endif // NETWORK_HEADERS_H