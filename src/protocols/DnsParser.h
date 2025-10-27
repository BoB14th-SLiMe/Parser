#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "BaseProtocolParser.h"

class DnsParser : public BaseProtocolParser {
public:
    ~DnsParser() override;
    
    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;

    // --- 추가: CSV 헤더 오버라이드 ---
    void writeCsvHeader(std::ofstream& csv_stream) override;
};

#endif // DNS_PARSER_H
