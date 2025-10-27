#ifndef IPROTOCOL_PARSER_H
#define IPROTOCOL_PARSER_H

#include <string>
#include <fstream>
#include <vector>
#include "pcap.h"

// Forward declaration
class TimeBasedCsvWriter;

// Packet information structure passed to parsers
struct PacketInfo {
    std::string timestamp;
    std::string flow_id;
    std::string src_mac;
    std::string dst_mac;
    uint16_t eth_type = 0; // 이더넷 타입 추가
    std::string src_ip;
    uint16_t src_port = 0;
    std::string dst_ip;
    uint16_t dst_port = 0;
    uint8_t protocol = 0; // IP 계층 프로토콜 (e.g., IPPROTO_TCP, IPPROTO_UDP)
    uint32_t tcp_seq = 0;
    uint32_t tcp_ack = 0;
    uint8_t tcp_flags = 0;
    const u_char* payload = nullptr;
    int payload_size = 0;
};

class IProtocolParser {
public:
    virtual ~IProtocolParser();

    virtual std::string getName() const = 0;
    virtual bool isProtocol(const PacketInfo& info) const = 0;
    virtual void parse(const PacketInfo& info) = 0;
    
    virtual void setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) = 0;
    
    // TimeBasedCsvWriter 설정
    virtual void setTimeBasedWriter(TimeBasedCsvWriter* writer) = 0;
    
    virtual void writeCsvHeader(std::ofstream& csv_stream) = 0;
};

#endif // IPROTOCOL_PARSER_H