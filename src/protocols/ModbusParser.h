#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include "BaseProtocolParser.h"
#include "../AssetManager.h"
#include <map>

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

private:
    AssetManager& m_assetManager;
    std::map<std::string, std::map<uint32_t, ModbusRequestInfo>> m_pending_requests;
};

#endif // MODBUS_PARSER_H