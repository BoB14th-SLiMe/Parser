#ifndef GENERIC_PARSER_H
#define GENERIC_PARSER_H

#include "IProtocolParser.h"

class GenericParser : public IProtocolParser {
public:
    explicit GenericParser(const std::string& name);
    ~GenericParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
    void setOutputStream(std::ofstream* stream) override;

private:
    std::string m_name;
    std::ofstream* m_output_stream = nullptr;
};

#endif // GENERIC_PARSER_H
