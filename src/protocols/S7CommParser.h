#ifndef S7COMM_PARSER_H
#define S7COMM_PARSER_H

#include "BaseProtocolParser.h"
#include <chrono>
#include <vector>
#include <map> // <map> 헤더 추가

// S7comm 아이템 구조체 (요청 파싱 시 사용)
struct S7CommItem {
    // Python 스크립트에서 S7CommItem의 내용을 펼치므로, 
    // 응답 파싱을 위해 요청의 아이템 개수만 알아도 됩니다.
    // (간단하게 유지하기 위해 비워둠)
};

// S7comm 요청 정보 구조체
struct S7CommRequestInfo {
    uint16_t pdu_ref = 0;
    uint8_t function_code = 0;
    std::vector<S7CommItem> items; // 요청의 아이템 리스트 (응답 파싱 시 개수 참조용)
    std::chrono::steady_clock::time_point timestamp;
};

class S7CommParser : public BaseProtocolParser {
public:
    ~S7CommParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

    // --- 추가: CSV 헤더 오버라이드 ---
    void writeCsvHeader(std::ofstream& csv_stream) override;

private:
    // S7comm 프로토콜에 대한 보류 중인 요청 맵
    std::map<std::string, std::map<uint16_t, S7CommRequestInfo>> m_pending_requests;
};

#endif // S7COMM_PARSER_H
