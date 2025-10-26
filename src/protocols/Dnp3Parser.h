#ifndef DNP3_PARSER_H
#define DNP3_PARSER_H

#include "BaseProtocolParser.h" 

class Dnp3Parser : public BaseProtocolParser {
public:
    ~Dnp3Parser() override;
    
    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

    // --- 추가: CSV 헤더 오버라이드 ---
    void writeCsvHeader(std::ofstream& csv_stream) override;
};

#endif // DNP3_PARSER_H
