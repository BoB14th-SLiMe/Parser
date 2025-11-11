#ifndef DNP3_PARSER_H
#define DNP3_PARSER_H

#include "BaseProtocolParser.h"

class Dnp3Parser : public BaseProtocolParser {
public:
    ~Dnp3Parser() override;
    
    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;
};

#endif // DNP3_PARSER_H