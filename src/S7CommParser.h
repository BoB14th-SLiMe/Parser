#ifndef S7COMM_PARSER_H
#define S7COMM_PARSER_H

#include "IProtocolParser.h"
#include <chrono>
#include <vector>

// S7comm 아이템 구조체
struct S7CommItem {
    uint8_t transport_size = 0;
    uint16_t length = 0;
    uint16_t db_number = 0;
    uint8_t area = 0;
    uint32_t address = 0;
};

// S7comm 요청 정보 구조체
struct S7CommRequestInfo {
    uint16_t pdu_ref = 0;
    uint8_t function_code = 0;
    std::vector<S7CommItem> items;
    std::chrono::steady_clock::time_point timestamp;
};

class S7CommParser : public IProtocolParser {
public:
    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
    void setOutputStream(std::ofstream* stream) override;

private:
    std::string parse_pdu(const u_char* pdu, int pdu_len, bool is_request, const S7CommRequestInfo* req_info);

    // S7comm 프로토콜에 대한 보류 중인 요청 맵
    std::map<std::string, std::map<uint16_t, S7CommRequestInfo>> m_pending_requests;
    std::ofstream* m_output_stream = nullptr;
};

#endif // S7COMM_PARSER_H
