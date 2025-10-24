#ifndef BASE_PROTOCOL_PARSER_H
#define BASE_PROTOCOL_PARSER_H

#include "IProtocolParser.h"

class BaseProtocolParser : public IProtocolParser {
public:
    // --- 수정: 소멸자 선언 (정의는 .cpp 파일로 이동) ---
    ~BaseProtocolParser() override;
    
    // 수정: json과 csv 출력을 위한 스트림 설정
    void setOutputStream(std::ofstream* json_stream, std::ofstream* csv_stream) override;

protected:
    // --- 수정: direction 파라미터 추가 ---
    void writeOutput(const PacketInfo& info, const std::string& details_json, const std::string& direction);

    std::ofstream* m_json_stream = nullptr;
    std::ofstream* m_csv_stream = nullptr;

private:
    // 추가: CSV 이스케이프 처리 헬퍼
    std::string escape_csv(const std::string& s);
};

#endif // BASE_PROTOCOL_PARSER_H

