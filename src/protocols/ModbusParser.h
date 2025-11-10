#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h"
#include <map>
#include <chrono>

struct ModbusRequestInfo {
    uint8_t function_code = 0;
    uint16_t start_address = 0;
    std::chrono::steady_clock::time_point timestamp;
};

class ModbusParser : public BaseProtocolParser {
public:
    explicit ModbusParser(AssetManager& assetManager);
    ~ModbusParser() override;
    
    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;

private:
    AssetManager& m_assetManager;
    std::map<std::string, std::map<uint32_t, ModbusRequestInfo>> m_pending_requests;
    
    // 타임아웃 정리 (선택사항 - 프로덕션에서 사용)
    std::chrono::steady_clock::time_point m_last_cleanup = std::chrono::steady_clock::now();
    
    void cleanupOldRequests() {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - m_last_cleanup).count() < 60) {
            return; // 1분마다만 정리
        }
        
        for (auto& flow_pair : m_pending_requests) {
            for (auto it = flow_pair.second.begin(); it != flow_pair.second.end();) {
                // 5분 이상 된 요청 삭제
                if (std::chrono::duration_cast<std::chrono::minutes>(now - it->second.timestamp).count() > 5) {
                    it = flow_pair.second.erase(it);
                } else {
                    ++it;
                }
            }
        }
        m_last_cleanup = now;
    }
};

#endif // MODBUS_PARSER_H