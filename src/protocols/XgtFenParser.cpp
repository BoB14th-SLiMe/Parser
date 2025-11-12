#include "XgtFenParser.h"
#include "../UnifiedWriter.h"  // ← 추가!
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include "../network/network_headers.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

const uint16_t XGT_DTYPE_BIT = 0x0000;
const uint16_t XGT_DTYPE_BYTE = 0x0001;
const uint16_t XGT_DTYPE_WORD = 0x0002;
const uint16_t XGT_DTYPE_DWORD = 0x0003;
const uint16_t XGT_DTYPE_LWORD = 0x0004;
const uint16_t XGT_DTYPE_CONTINUOUS = 0x0014;  // LE of 0x1400

const uint16_t XGT_CMD_READ_REQ = 0x0054;      // LE of 0x5400
const uint16_t XGT_CMD_READ_RESP = 0x0055;     // LE of 0x5500
const uint16_t XGT_CMD_WRITE_REQ = 0x0058;     // LE of 0x5800
const uint16_t XGT_CMD_WRITE_RESP = 0x0059;    // LE of 0x5900

const uint16_t XGT_ERROR_STATUS_OK = 0x0000;
const uint16_t XGT_ERROR_STATUS_ERR = 0xFFFF;


// Helper function implementation to read little-endian values
template <typename T>
T read_le(const u_char* buffer) {
    T value;
    memcpy(&value, buffer, sizeof(T));
    return value;
}

// Helper function to convert byte array to hex string for display
std::string XgtFenParser::bytesToHexString(const uint8_t* bytes, size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

XgtFenParser::XgtFenParser(AssetManager& assetManager)
    : m_assetManager(assetManager) {}

XgtFenParser::~XgtFenParser() {}

std::string XgtFenParser::getName() const {
    return "xgt_fen";
}

bool XgtFenParser::isProtocol(const PacketInfo& info) const {
    return ((info.protocol == IPPROTO_TCP || info.protocol == IPPROTO_UDP) &&
           (info.dst_port == 2004 || info.src_port == 2004) &&
           info.payload_size >= 20 &&
           memcmp(info.payload, "LSIS-XGT", 8) == 0);
}

bool XgtFenParser::parseHeader(const u_char* payload, size_t size, XgtFenHeader& header) {
    if (size < 20) return false;

    header.companyId.assign(reinterpret_cast<const char*>(payload), 8);
    header.reserved1 = read_le<uint16_t>(payload + 8);
    header.plcInfo = read_le<uint16_t>(payload + 10);
    header.cpuInfo = payload[12];
    header.sourceOfFrame = payload[13];
    header.invokeId = read_le<uint16_t>(payload + 14);
    header.length = read_le<uint16_t>(payload + 16);
    header.fenetPosition = payload[18];
    header.reserved2 = payload[19];

    if (header.companyId != "LSIS-XGT") return false;

    return true;
}

bool XgtFenParser::parseInstruction(const u_char* inst_payload, size_t inst_size, 
                                     const XgtFenHeader& header, XgtFenInstruction& instruction) {
    if (inst_size < 4) {
        std::cerr << "[XGT] Instruction too short: " << inst_size << " bytes" << std::endl;
        return false;
    }

    // 명령어와 데이터 타입 읽기
    instruction.command = read_le<uint16_t>(inst_payload);
    instruction.dataType = read_le<uint16_t>(inst_payload + 2);
    instruction.is_continuous = (instruction.dataType == XGT_DTYPE_CONTINUOUS);
    size_t offset = 4;

    // 요청/응답 판별
    bool is_response = (header.sourceOfFrame == 0x11);
    bool is_request = (header.sourceOfFrame == 0x33);
    bool is_read_cmd = (instruction.command == XGT_CMD_READ_REQ || 
                       instruction.command == XGT_CMD_READ_RESP);
    bool is_write_cmd = (instruction.command == XGT_CMD_WRITE_REQ || 
                        instruction.command == XGT_CMD_WRITE_RESP);

    if (!is_read_cmd && !is_write_cmd) {
        std::cerr << "[XGT] Unknown command: 0x" << std::hex << instruction.command << std::endl;
        return false;
    }

    // Reserved 필드 (2 bytes)
    if (inst_size < offset + 2) return false;
    instruction.reserved = read_le<uint16_t>(inst_payload + offset);
    offset += 2;

    // === 응답 프레임 파싱 ===
    if (is_response) {
        // 에러 상태 (2 bytes)
        if (inst_size < offset + 2) return false;
        instruction.errorStatus = read_le<uint16_t>(inst_payload + offset);
        offset += 2;

        // 블록 개수 또는 에러 정보 (2 bytes)
        if (inst_size < offset + 2) return false;
        instruction.errorInfoOrBlockCount = read_le<uint16_t>(inst_payload + offset);
        offset += 2;

        // 에러 발생 시 종료
        if (instruction.errorStatus != XGT_ERROR_STATUS_OK) {
            std::cerr << "[XGT] Error status: 0x" << std::hex << instruction.errorStatus 
                      << ", Error info: 0x" << instruction.errorInfoOrBlockCount << std::endl;
            return true;  // 에러도 유효한 응답
        }

        // 정상 응답 데이터 파싱
        if (is_read_cmd) {
            if (instruction.is_continuous) {
                // === 연속 읽기 응답 ===
                // 블록 개수는 이미 읽음 (항상 1)
                
                // 데이터 크기 (2 bytes)
                if (inst_size < offset + 2) {
                    std::cerr << "[XGT] Missing data size for continuous read response" << std::endl;
                    return false;
                }
                instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
                offset += 2;

                // 데이터 읽기
                if (inst_size < offset + instruction.dataSize) {
                    std::cerr << "[XGT] Insufficient data: expected " << instruction.dataSize 
                              << ", available " << (inst_size - offset) << std::endl;
                    return false;
                }
                instruction.continuousReadData.assign(inst_payload + offset, 
                                                     inst_payload + offset + instruction.dataSize);
                offset += instruction.dataSize;
            } else {
                // === 개별 읽기 응답 ===
                instruction.blockCount = instruction.errorInfoOrBlockCount;
                
                for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                    // 데이터 길이 (2 bytes)
                    if (inst_size < offset + 2) {
                        std::cerr << "[XGT] Missing data length for block " << i << std::endl;
                        return false;
                    }
                    uint16_t data_len = read_le<uint16_t>(inst_payload + offset);
                    offset += 2;

                    // 데이터 읽기
                    if (inst_size < offset + data_len) {
                        std::cerr << "[XGT] Insufficient data for block " << i << std::endl;
                        return false;
                    }
                    std::vector<uint8_t> data_bytes(inst_payload + offset, 
                                                    inst_payload + offset + data_len);
                    instruction.readData.push_back({data_len, std::move(data_bytes)});
                    offset += data_len;
                }
            }
        } else {
            // === 쓰기 응답 ===
            // 쓰기 응답에는 데이터가 없음, 블록 개수만 있음
            instruction.blockCount = instruction.errorInfoOrBlockCount;
        }
    }
    // === 요청 프레임 파싱 ===
    else if (is_request) {
        // 블록 개수 (2 bytes)
        if (inst_size < offset + 2) return false;
        instruction.blockCount = read_le<uint16_t>(inst_payload + offset);
        offset += 2;

        if (instruction.is_continuous) {
            // === 연속 읽기/쓰기 요청 ===
            if (instruction.blockCount != 1) {
                std::cerr << "[XGT] Continuous request must have blockCount=1, got " 
                          << instruction.blockCount << std::endl;
                return false;
            }

            // 변수명 길이 (2 bytes)
            if (inst_size < offset + 2) return false;
            uint16_t var_len = read_le<uint16_t>(inst_payload + offset);
            offset += 2;

            // 변수명 읽기
            if (inst_size < offset + var_len) {
                std::cerr << "[XGT] Insufficient space for variable name" << std::endl;
                return false;
            }
            instruction.variableName.assign(reinterpret_cast<const char*>(inst_payload + offset), var_len);
            offset += var_len;

            // 연속 읽기/쓰기는 반드시 Byte 타입 변수여야 함 (%MB, %DB, %PB)
            if (var_len >= 3) {
                char type_indicator = instruction.variableName[2];
                if (type_indicator != 'B' && type_indicator != 'b') {
                    std::cerr << "[XGT] Continuous read/write requires Byte type variable (e.g., %MB, %DB), got: " 
                              << instruction.variableName << std::endl;
                    // Warning만 출력하고 계속 진행 (일부 구현은 허용할 수 있음)
                }
            }

            // 데이터 크기 (2 bytes)
            if (inst_size < offset + 2) return false;
            instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
            offset += 2;

            if (is_write_cmd) {
                // 연속 쓰기: 데이터 읽기
                if (inst_size < offset + instruction.dataSize) {
                    std::cerr << "[XGT] Insufficient write data" << std::endl;
                    return false;
                }
                instruction.continuousReadData.assign(inst_payload + offset, 
                                                     inst_payload + offset + instruction.dataSize);
                offset += instruction.dataSize;
            }
            // 연속 읽기 요청은 데이터 없음
        } else {
            // === 개별 읽기/쓰기 요청 ===
            
            // 1단계: 모든 변수명 읽기
            for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                // 변수명 길이 (2 bytes)
                if (inst_size < offset + 2) {
                    std::cerr << "[XGT] Missing variable length for block " << i << std::endl;
                    return false;
                }
                uint16_t var_len = read_le<uint16_t>(inst_payload + offset);
                offset += 2;

                // 변수명 읽기
                if (inst_size < offset + var_len) {
                    std::cerr << "[XGT] Insufficient space for variable " << i << std::endl;
                    return false;
                }
                std::string var_name(reinterpret_cast<const char*>(inst_payload + offset), var_len);
                instruction.variables.push_back({var_len, std::move(var_name)});
                offset += var_len;
            }

            // 2단계: 쓰기 요청인 경우 모든 데이터 읽기
            if (is_write_cmd) {
                for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                    // 데이터 길이 (2 bytes)
                    if (inst_size < offset + 2) {
                        std::cerr << "[XGT] Missing data length for block " << i << std::endl;
                        return false;
                    }
                    uint16_t data_len = read_le<uint16_t>(inst_payload + offset);
                    offset += 2;

                    // 데이터 읽기
                    if (inst_size < offset + data_len) {
                        std::cerr << "[XGT] Insufficient write data for block " << i << std::endl;
                        return false;
                    }
                    std::vector<uint8_t> data_bytes(inst_payload + offset, 
                                                    inst_payload + offset + data_len);
                    instruction.writeData.push_back({data_len, std::move(data_bytes)});
                    offset += data_len;
                }
            }
            // 개별 읽기 요청은 데이터 없음
        }
    } else {
        std::cerr << "[XGT] Invalid source of frame: 0x" << std::hex 
                  << (int)header.sourceOfFrame << std::endl;
        return false;
    }

    // 파싱 완료 검증
    if (offset != inst_size) {
        std::cerr << "[XGT] Parsing mismatch: parsed " << offset 
                  << " bytes, expected " << inst_size << " bytes" << std::endl;
        return false;
    }

    return true;
}

void XgtFenParser::parse(const PacketInfo& info) {
    XgtFenHeader header;
    if (!parseHeader(info.payload, info.payload_size, header)) {
        return;
    }

    if (20 + header.length != info.payload_size) {
        std::cerr << "XGT FEN Size Mismatch. Header len: " << header.length
                  << ", Actual inst size: " << (info.payload_size - 20)
                  << ". Timestamp: " << info.timestamp << std::endl;
    }

    XgtFenInstruction instruction = {};
    const u_char* instruction_payload = info.payload + 20;
    size_t instruction_size = std::min(static_cast<size_t>(header.length),
                                       static_cast<size_t>(info.payload_size > 20 ? info.payload_size - 20 : 0));

    bool parse_success = parseInstruction(instruction_payload, instruction_size, header, instruction);

    std::string direction = (header.sourceOfFrame == 0x33) ? "request" : 
                           (header.sourceOfFrame == 0x11 ? "response" : "unknown");

    // UnifiedRecord 생성
    UnifiedRecord record = createUnifiedRecord(info, direction);

    // Set XGT-FEN datagram length (instruction data length from header)
    // This is the application layer data length, not including the 20-byte XGT header
    record.len = std::to_string(header.length);

    // XGT 공통 필드
    record.xgt_prid = std::to_string(header.invokeId);
    record.xgt_companyId = header.companyId;
    record.xgt_plcinfo = std::to_string(header.plcInfo);
    record.xgt_cpuinfo = std::to_string(header.cpuInfo);
    record.xgt_source = std::to_string(header.sourceOfFrame);
    record.xgt_len = std::to_string(header.length);
    record.xgt_fenetpos = std::to_string(header.fenetPosition);

    if (parse_success) {
        record.xgt_cmd = std::to_string(instruction.command);
        record.xgt_dtype = std::to_string(instruction.dataType);
        record.xgt_blkcnt = std::to_string(instruction.blockCount);
        record.xgt_errstat = std::to_string(instruction.errorStatus);
        record.xgt_errinfo = std::to_string(instruction.errorInfoOrBlockCount);
        
        if (instruction.dataSize > 0) {
            record.xgt_datasize = std::to_string(instruction.dataSize);
        }

        // Variables
        std::string vars_csv;
        if (!instruction.variableName.empty()) {
            vars_csv = instruction.variableName;
        } else {
            for(size_t i = 0; i < instruction.variables.size(); ++i) {
                vars_csv += instruction.variables[i].second;
                if (i < instruction.variables.size() - 1) vars_csv += ";";
            }
        }
        record.xgt_vars = vars_csv;

        // Data
        std::string data_csv;
        if (!instruction.continuousReadData.empty()) {
            data_csv = bytesToHexString(instruction.continuousReadData.data(), 
                                       instruction.continuousReadData.size());
        } else if (!instruction.readData.empty()) {
            data_csv = bytesToHexString(instruction.readData[0].second.data(), 
                                       instruction.readData[0].second.size());
            if(instruction.readData.size() > 1) 
                data_csv += "...(" + std::to_string(instruction.readData.size()) + " items)";
        } else if (!instruction.writeData.empty()) {
            data_csv = bytesToHexString(instruction.writeData[0].second.data(), 
                                       instruction.writeData[0].second.size());
            if(instruction.writeData.size() > 1) 
                data_csv += "...(" + std::to_string(instruction.writeData.size()) + " items)";
        }
        record.xgt_data = data_csv;

        // Translated address 및 description
        std::string primary_var_name;
        if (!instruction.variableName.empty()) {
            primary_var_name = instruction.variableName;
        } else if (!instruction.variables.empty()) {
            primary_var_name = instruction.variables[0].second;
        }
        
        if (!primary_var_name.empty()) {
            std::string translatedAddr = m_assetManager.translateXgtAddress(primary_var_name);
            record.xgt_translated_addr = translatedAddr;
            record.xgt_description = m_assetManager.getDescription(translatedAddr);
        }
    }

    addUnifiedRecord(record);
}