#ifndef S7COMM_PARSER_H
#define S7COMM_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h"
#include <chrono>
#include <vector>
#include <map>

struct S7CommItem {};

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

private:
    AssetManager& m_assetManager;
    std::map<std::string, std::map<uint16_t, S7CommRequestInfo>> m_pending_requests;
};

#endif // S7COMM_PARSER_H