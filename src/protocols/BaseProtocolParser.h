#ifndef BASE_PROTOCOL_PARSER_H
#define BASE_PROTOCOL_PARSER_H

#include "IProtocolParser.h"

// Forward declaration
class TimeBasedCsvWriter;

class BaseProtocolParser : public IProtocolParser {
public:
    ~BaseProtocolParser() override;

    static std::string mac_to_string(const uint8_t* mac);
    
    void setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) override;
    
    void setTimeBasedWriter(TimeBasedCsvWriter* writer) override {
        m_time_writer = writer;
    }

    bool isProtocol(const PacketInfo& info) const override { return false; }

    void writeCsvHeader(std::ofstream& csv_stream) override;

protected:
    // JSONL 작성을 위한 헬퍼
    void writeJsonl(const PacketInfo& info, const std::string& direction, const std::string& details_json_content);

    // 기본 CSV 라인 (d 컬럼 포함)
    void writeBaseCsvLine(const PacketInfo& info, const std::string& direction, const std::string& details_json_content);
    
    // CSV 라인을 쓰고 TimeBasedWriter에도 전달
    void writeCsvLineAndCapture(const std::string& csv_line);

    // CSV 이스케이프 헬퍼
    std::string escape_csv(const std::string& s);

    std::ofstream* m_json_stream = nullptr;
    std::ofstream* m_csv_stream = nullptr;
    TimeBasedCsvWriter* m_time_writer = nullptr;
};

#endif // BASE_PROTOCOL_PARSER_H