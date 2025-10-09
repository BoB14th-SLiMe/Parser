#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include "IProtocolParser.h"

class DnsParser : public IProtocolParser {
public:
    ~DnsParser() override;
    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
    void setOutputStream(std::ofstream* stream) override;

private:
    std::ofstream* m_output_stream = nullptr;
};

#endif // DNS_PARSER_H
