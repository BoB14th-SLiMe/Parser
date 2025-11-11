#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include "BaseProtocolParser.h"

class ArpParser : public BaseProtocolParser {
public:
    ArpParser();
    ~ArpParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;
};

#endif // ARP_PARSER_H