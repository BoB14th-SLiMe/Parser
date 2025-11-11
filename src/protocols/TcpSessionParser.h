#ifndef TCP_SESSION_PARSER_H
#define TCP_SESSION_PARSER_H

#include "BaseProtocolParser.h"

class TcpSessionParser : public BaseProtocolParser {
public:
    TcpSessionParser();
    ~TcpSessionParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;
};

#endif // TCP_SESSION_PARSER_H