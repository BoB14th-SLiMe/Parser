#ifndef UNKNOWN_PARSER_H
#define UNKNOWN_PARSER_H

#include "BaseProtocolParser.h"

class UnknownParser : public BaseProtocolParser {
public:
    ~UnknownParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;
};

#endif // UNKNOWN_PARSER_H