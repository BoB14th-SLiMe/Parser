#ifndef DNP3_PARSER_H
#define DNP3_PARSER_H

#include "IProtocolParser.h"

class Dnp3Parser : public IProtocolParser {
public:
    ~Dnp3Parser() override;
    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
    void setOutputStream(std::ofstream* stream) override;

private:
    std::ofstream* m_output_stream = nullptr;
};

#endif // DNP3_PARSER_H
