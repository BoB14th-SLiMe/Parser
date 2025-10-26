#ifndef TCP_SESSION_PARSER_H
#define TCP_SESSION_PARSER_H

#include <string>
#include <sstream>
#include <cstdint>
#include <tuple>

class TcpSessionParser {
public:
    TcpSessionParser();
    ~TcpSessionParser();

    // --- 수정: JSON 문자열만 반환 (비어있는 JSON "{}") ---
    std::string parse(uint32_t seq, uint32_t ack, uint8_t flags) const;
    
    std::string getName() const;
};

#endif // TCP_SESSION_PARSER_H
