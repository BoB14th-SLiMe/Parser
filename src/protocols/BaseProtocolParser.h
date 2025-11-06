#ifndef BASE_PROTOCOL_PARSER_H
#define BASE_PROTOCOL_PARSER_H

#include "IProtocolParser.h"
#include <string>
#include <fstream>

// Forward declaration
class UnifiedWriter;
struct UnifiedRecord;

class BaseProtocolParser : public IProtocolParser {
public:
    virtual ~BaseProtocolParser();

    static std::string mac_to_string(const uint8_t* mac);
    
    void setUnifiedWriter(UnifiedWriter* writer) override {
        m_unified_writer = writer;
    }

    bool isProtocol(const PacketInfo& info) const override { 
        return false; 
    }

protected:
    // UnifiedRecord 생성 헬퍼 함수
    UnifiedRecord createUnifiedRecord(const PacketInfo& info, const std::string& direction);
    
    // 레코드를 UnifiedWriter에 추가
    void addUnifiedRecord(const UnifiedRecord& record);
    
    // CSV 이스케이프 헬퍼
    std::string escape_csv(const std::string& s);

    UnifiedWriter* m_unified_writer = nullptr;
};

#endif // BASE_PROTOCOL_PARSER_H