#ifndef GENERIC_PARSER_H
#define GENERIC_PARSER_H

#include "BaseProtocolParser.h"

class GenericParser : public BaseProtocolParser {
public:
    explicit GenericParser(const std::string& name);
    ~GenericParser() override;

    std::string getName() const override;
    bool isProtocol(const PacketInfo& info) const override;
    void parse(const PacketInfo& info) override;

private:
    std::string m_name;
};

#endif // GENERIC_PARSER_H