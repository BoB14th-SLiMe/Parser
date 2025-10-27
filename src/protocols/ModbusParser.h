#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h" // AssetManager 헤더 포함
#include <map>

// Modbus 요청 정보를 저장하는 구조체
struct ModbusRequestInfo {
    uint8_t function_code = 0;
    uint16_t start_address = 0;
};

class ModbusParser : public BaseProtocolParser {
public:
    explicit ModbusParser(AssetManager& assetManager);
    ~ModbusParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;

    void writeCsvHeader(std::ofstream& csv_stream) override;

private:
    AssetManager& m_assetManager;
    std::map<std::string, std::map<uint16_t, ModbusRequestInfo>> m_pending_requests;
};

#endif // MODBUS_PARSER_H
