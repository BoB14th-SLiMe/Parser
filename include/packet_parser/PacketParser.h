#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <fstream>
#include <string>
#include <map> // 여러 파일 스트림을 관리하기 위해 추가

class PacketParser {
public:
    // 생성자: 기본 출력 디렉토리 설정
    PacketParser(const std::string& output_dir = "output/");
    
    // 소멸자: 모든 파일 스트림을 안전하게 닫는다.
    ~PacketParser();

    // 패킷 파싱 메인 함수
    void parse(const u_char* packet);

private:
    std::string m_output_dir;
    // 프로토콜 이름과 파일 스트림을 매핑하여 관리
    std::map<std::string, std::ofstream> m_file_streams;

    // 데이터를 CSV 형식의 한 줄로 변환하는 헬퍼 함수
    std::string format_payload_to_hex(const u_char* payload, int size);

    // 프로토콜 이름에 해당하는 파일 스트림을 가져오거나 새로 생성하는 함수
    std::ofstream& get_file_stream(const std::string& protocol);
};

#endif // PACKET_PARSER_H

