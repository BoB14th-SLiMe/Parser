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

// --- 추가: XGT 파싱 결과를 담을 구조체 ---
struct XgtFenParsedData {
    std::string cmd;
    std::string dt;
    std::string bc;
    std::string err;
    std::string ecode;
    
    std::string var_nm;
    std::string var_len;
    std::string data_hex;
};


class XgtFenParser : public BaseProtocolParser {
public:
    ~XgtFenParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

    // --- 추가: CSV 헤더 오버라이드 ---
    void writeCsvHeader(std::ofstream& csv_stream) override;

private:
    // Flow ID와 Invoke ID를 키로 사용하여 보류 중인 요청을 관리
    std::map<std::string, std::map<uint16_t, XgtFenRequestInfo>> m_pending_requests;

    // --- 추가: CSV 출력을 위한 구조적 파서 ---
    XgtFenParsedData parse_pdu_structured(const u_char* pdu, int pdu_len, bool is_response);
};

#endif // XGT_FEN_PARSER_H
