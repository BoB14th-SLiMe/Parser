#ifndef UNKNOWN_PARSER_H
#define UNKNOWN_PARSER_H

#include "IProtocolParser.h"

class UnknownParser : public IProtocolParser {
public:
    ~UnknownParser() override;
    std::string getName() const override;
    // 어떤 프로토콜에도 해당하지 않는 패킷을 처리하기 위해 항상 true를 반환
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
    void setOutputStream(std::ofstream* stream) override;

private:
    std::ofstream* m_output_stream = nullptr;
};

#endif // UNKNOWN_PARSER_H
