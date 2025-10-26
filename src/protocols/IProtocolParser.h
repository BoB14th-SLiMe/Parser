#ifndef IPROTOCOL_PARSER_H
#define IPROTOCOL_PARSER_H

#include <string>
#include <fstream>
#include <vector>
#include "pcap.h"

// Packet information structure passed to parsers
struct PacketInfo {
    std::string timestamp;
    std::string flow_id;
    // --- 추가: MAC 주소 ---
    std::string src_mac;
    std::string dst_mac;
    // ---
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    const u_char* payload;
    int payload_size;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_flags;
};

class IProtocolParser {
public:
    // --- MODIFICATION: Declare the virtual destructor without a definition or '= default' ---
    virtual ~IProtocolParser();

    virtual std::string getName() const = 0;
    virtual bool isProtocol(const u_char* payload, int size) const = 0;
    virtual void parse(const PacketInfo& info) = 0;
    virtual void setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) = 0;
};

#endif // IPROTOCOL_PARSER_H

