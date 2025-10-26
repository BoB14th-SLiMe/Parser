#ifndef UNKNOWN_PARSER_H
#define UNKNOWN_PARSER_H

#include "BaseProtocolParser.h" // BaseProtocolParser를 포함

// BaseProtocolParser를 상속받도록 수정
class UnknownParser : public BaseProtocolParser {
public:
    ~UnknownParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;

    // --- 추가: CSV 헤더 오버라이드 ---
    void writeCsvHeader(std::ofstream& csv_stream) override;
};

#endif // UNKNOWN_PARSER_H
