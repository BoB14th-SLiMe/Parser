#ifndef S7COMM_PARSER_H
#define S7COMM_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h" // AssetManager 헤더 포함
#include <chrono>
#include <vector>
#include <map>

// S7comm 아이템 구조체 (요청 파싱 시 사용)
struct S7CommItem {
    // (내용 생략)
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
    explicit S7CommParser(AssetManager& assetManager);
    ~S7CommParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;

    void writeCsvHeader(std::ofstream& csv_stream) override;

private:
    AssetManager& m_assetManager;
    std::map<std::string, std::map<uint16_t, S7CommRequestInfo>> m_pending_requests;
};

#endif // S7COMM_PARSER_H
