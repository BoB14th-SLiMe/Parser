#ifndef XGT_FEN_PARSER_H
#define XGT_FEN_PARSER_H

#include "BaseProtocolParser.h"
#include <chrono>
#include <vector>
#include <map>
#include <string>

// FEnet 요청에 대한 정보를 저장하는 구조체
struct XgtFenRequestInfo {
    uint16_t invoke_id = 0;
    uint16_t command = 0;
    uint16_t data_type = 0;
    std::chrono::steady_clock::time_point timestamp;
};

class XgtFenParser : public BaseProtocolParser {
public:
    // --- 수정: 소멸자를 여기서 선언합니다 ---
    ~XgtFenParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

private:
    // Flow ID와 Invoke ID를 키로 사용하여 보류 중인 요청을 관리
    std::map<std::string, std::map<uint16_t, XgtFenRequestInfo>> m_pending_requests;
};

#endif // XGT_FEN_PARSER_H

