#ifndef MODBUS_PARSER_H
#define MODBUS_PARSER_H

#include "BaseProtocolParser.h"
#include <map>
#include <string>

// Modbus 요청 상태를 추적하기 위한 내부 구조체
// (ModbusParser.cpp의 parse 함수에서 응답 파싱 시 사용됨)
struct ModbusRequestInfo {
    uint8_t function_code = 0;
    uint16_t start_address = 0;
};

class ModbusParser : public BaseProtocolParser {
public:
    ModbusParser(); // <- 1번 오류 해결 (생성자 선언)
    ~ModbusParser() override;
    
    std::string getName() const override;

    // <- 2번 오류 해결 (인터페이스와 일치하는 시그니처 선언)
    bool isProtocol(const u_char* payload, int size) const override;
    
    void parse(const PacketInfo& info) override;
    void writeCsvHeader(std::ofstream& csv_stream) override;

private:
    // parse 함수에서 사용되는 멤버 변수
    // FlowKey: "ClientIP:ClientPort->ServerIP:ServerPort"
    // RequestKey: (TransactionID << 8) | FunctionCode
    std::map<std::string, std::map<uint32_t, ModbusRequestInfo>> m_pending_requests;
};

#endif // MODBUS_PARSER_H