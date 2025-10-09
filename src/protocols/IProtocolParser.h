#ifndef I_PROTOCOL_PARSER_H
#define I_PROTOCOL_PARSER_H

#include <string>
#include <fstream>
#include <map>
#include <pcap.h>
#include "../network/network_headers.h"

// 파서 간에 공통 패킷 정보를 전달하기 위한 구조체
struct PacketInfo {
    const std::string& timestamp;
    const std::string& flow_id;
    const char* src_ip;
    uint16_t src_port;
    const char* dst_ip;
    uint16_t dst_port;
    const u_char* payload;
    int payload_size;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_flags;
};

// 모든 프로토콜 파서가 구현해야 하는 추상 기본 클래스
class IProtocolParser {
public:
    virtual ~IProtocolParser();

    virtual std::string getName() const = 0;
    virtual bool isProtocol(const u_char* payload, int size) const = 0;
    virtual void parse(const PacketInfo& info) = 0;
    virtual void setOutputStream(std::ofstream* stream) = 0;
};

#endif // I_PROTOCOL_PARSER_H