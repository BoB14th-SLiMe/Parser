#ifndef XGT_FEN_PARSER_H
#define XGT_FEN_PARSER_H

#include "IProtocolParser.h"
#include <chrono>
#include <vector>

// FEnet 요청에 대한 정보를 저장하는 구조체
struct XgtFenRequestInfo {
    uint16_t invoke_id = 0;
    uint16_t command = 0;
    uint16_t data_type = 0;
    std::chrono::steady_clock::time_point timestamp;
};

class XgtFenParser : public IProtocolParser {
public:
    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
    void setOutputStream(std::ofstream* stream) override;

private:
    std::string parse_pdu(const u_char* pdu, int pdu_len, bool is_request, const XgtFenRequestInfo* req_info);

    // Flow ID와 Invoke ID를 키로 사용하여 보류 중인 요청을 관리
    std::map<std::string, std::map<uint16_t, XgtFenRequestInfo>> m_pending_requests;
    std::ofstream* m_output_stream = nullptr;
};

#endif // XGT_FEN_PARSER_H