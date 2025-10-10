#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include "IProtocolParser.h"
#include <chrono>

// Modbus 요청 정보를 저장하는 구조체
struct ModbusRequestInfo {
    uint8_t function_code = 0;
    uint16_t start_address = 0; 
};

class ModbusParser : public IProtocolParser {
public:
    ~ModbusParser() override; // 소멸자 선언 추가

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
    void setOutputStream(std::ofstream* stream) override;

private:
    // Modbus 프로토콜에 대한 보류 중인 요청 맵
    std::map<std::string, std::map<uint16_t, ModbusRequestInfo>> m_pending_requests;
    std::ofstream* m_output_stream = nullptr;
};

#endif // MODBUS_PARSER_H
