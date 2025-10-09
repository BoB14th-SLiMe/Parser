#ifndef I_PROTOCOL_PARSER_H
#define I_PROTOCOL_PARSER_H

#include <string>
#include <fstream>
#include <map>
#include <pcap.h>
#include "network_headers.h"

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
};

// 모든 프로토콜 파서가 구현해야 하는 추상 기본 클래스
class IProtocolParser {
public:
    // 소멸자를 `= default` 없이 선언만 합니다.
    virtual ~IProtocolParser();

    // 프로토콜의 이름을 반환합니다 (예: "modbus_tcp").
    virtual std::string getName() const = 0;

    // 주어진 페이로드가 해당 프로토콜에 속하는지 확인합니다.
    virtual bool isProtocol(const u_char* payload, int size) const = 0;

    // 해당 프로토콜의 메인 파싱 로직을 수행합니다.
    virtual void parse(const PacketInfo& info) = 0;

    // 이 파서에 대한 출력 스트림을 설정합니다.
    virtual void setOutputStream(std::ofstream* stream) = 0;
};

#endif // I_PROTOCOL_PARSER_H

