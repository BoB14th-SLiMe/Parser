#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include "BaseProtocolParser.h"

class ArpParser : public BaseProtocolParser {
public:
    ArpParser() = default;
    ~ArpParser() override = default;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;
    void writeCsvHeader(std::ofstream& csv_stream) override;
};

#endif // ARP_PARSER_H