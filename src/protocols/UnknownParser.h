#ifndef UNKNOWN_PARSER_H
#define UNKNOWN_PARSER_H

#include "BaseProtocolParser.h" // BaseProtocolParser를 포함

// BaseProtocolParser를 상속받도록 수정
class UnknownParser : public BaseProtocolParser {
public:
    // --- 수정: 소멸자 선언 (정의는 .cpp 파일로 이동) ---
    ~UnknownParser() override;

    std::string getName() const override;
    bool isProtocol(const u_char* payload, int size) const override;
    void parse(const PacketInfo& info) override;
};

#endif // UNKNOWN_PARSER_H
