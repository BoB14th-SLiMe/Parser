#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h"
#include <map>
#include <list>
#include <chrono>
#include <mutex>

struct ModbusRequestInfo {
    uint16_t trans_id = 0;
    uint8_t function_code = 0;
    uint16_t base_address = 0;  // Start address from request
    uint16_t num_reg = 0;       // Number of registers from request
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

    // Shared across all ModbusParser instances (all worker threads)
    // Store list of all pending requests per flow (like Wireshark's wmem_list)
    // Key: flow_key, Value: list of requests (prepend new, search from head)
    static std::map<std::string, std::list<ModbusRequestInfo>> s_pending_requests;
    static std::mutex s_requests_mutex;  // Protect s_pending_requests from race conditions

    // 타임아웃 정리 (선택사항 - 프로덕션에서 사용)
    std::chrono::steady_clock::time_point m_last_cleanup = std::chrono::steady_clock::now();

    void cleanupOldRequests() {
        std::lock_guard<std::mutex> lock(s_requests_mutex);

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - m_last_cleanup).count() < 60) {
            return; // 1분마다만 정리
        }

        for (auto& flow_pair : s_pending_requests) {
            auto& req_list = flow_pair.second;
            // Remove requests older than 5 minutes
            req_list.remove_if([&now](const ModbusRequestInfo& req) {
                return std::chrono::duration_cast<std::chrono::minutes>(now - req.timestamp).count() > 5;
            });
        }
        m_last_cleanup = now;
    }
};

#endif // MODBUS_PARSER_H