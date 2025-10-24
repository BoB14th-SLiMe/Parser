#ifndef S7COMM_PARSER_H
#define S7COMM_PARSER_H

#include "BaseProtocolParser.h"
#include <chrono>
#include <vector>
#include <map> // <map> 헤더 추가

// S7comm 아이템 구조체
struct S7CommItem {
    // 응답 파싱 시 아이템 개수만 필요하므로 비워둘 수 있습니다.
};

// S7comm 요청 정보 구조체
struct S7CommRequestInfo {
    uint16_t pdu_ref = 0;
    uint8_t function_code = 0;
    std::vector<S7CommItem> items;
    std::chrono::steady_clock::time_point timestamp;
};

class S7CommParser : public BaseProtocolParser {
public:
    // --- 수정: 소멸자 선언 (정의는 .cpp 파일로 이동) ---
    ~S7CommParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

private:
    // S7comm 프로토콜에 대한 보류 중인 요청 맵
    std::map<std::string, std::map<uint16_t, S7CommRequestInfo>> m_pending_requests;
};

#endif // S7COMM_PARSER_H
