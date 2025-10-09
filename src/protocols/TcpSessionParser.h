#ifndef TCP_SESSION_PARSER_H
#define TCP_SESSION_PARSER_H

#include <string>
#include <sstream>
#include <cstdint>

class TcpSessionParser {
public:
    TcpSessionParser();
    ~TcpSessionParser();

    // TCP 세션 정보를 받아 간단한 JSON 문자열을 생성합니다.
    std::string parse(uint32_t seq, uint32_t ack, uint8_t flags) const;
    
    // 파서의 이름을 반환합니다.
    std::string getName() const;
};

#endif // TCP_SESSION_PARSER_H
