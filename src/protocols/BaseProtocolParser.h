#ifndef BASE_PROTOCOL_PARSER_H
#define BASE_PROTOCOL_PARSER_H

#include "IProtocolParser.h"

class BaseProtocolParser : public IProtocolParser {
public:
    ~BaseProtocolParser() override;
    
    // --- 수정: setOutputStream이 CSV 헤더 확인 로직 포함 ---
    void setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) override;

    // --- 수정: 기본 CSV 헤더 (d 컬럼만) ---
    void writeCsvHeader(std::ofstream& csv_stream) override;

protected:
    // --- 추가: JSONL 작성을 위한 헬퍼 ---
    void writeJsonl(const PacketInfo& info, const std::string& direction, const std::string& details_json_content);

    // --- 추가: 기본 CSV 라인 (d 컬럼 포함) ---
    void writeBaseCsvLine(std::ofstream& csv_stream, const PacketInfo& info, const std::string& direction, const std::string& details_json_content);

    // CSV 이스케이프 헬퍼
    std::string escape_csv(const std::string& s);

    std::ofstream* m_json_stream = nullptr;
    std::ofstream* m_csv_stream = nullptr;
};

#endif // BASE_PROTOCOL_PARSER_H
