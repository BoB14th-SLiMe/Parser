#ifndef UDP_SESSION_PARSER_H
#define UDP_SESSION_PARSER_H

#include "BaseProtocolParser.h"

class UdpSessionParser : public BaseProtocolParser {
public:
    UdpSessionParser();
    ~UdpSessionParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;
};

#endif // UDP_SESSION_PARSER_H