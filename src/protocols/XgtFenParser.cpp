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
                // 블록 개수는 항상 1 (errorInfoOrBlockCount에서 읽은 값)
                instruction.blockCount = instruction.errorInfoOrBlockCount;

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

    // Set XGT-FEN datagram length (TCP payload length to match wireshark_parser)
    // This includes the 20-byte XGT header + instruction data
    record.len = std::to_string(info.payload_size);

    // XGT 공통 필드 - Python 필드명과 일치 (xgt_fen_*), 16진수 형식 사용
    record.xgt_fen_prid = std::to_string(header.invokeId);
    record.xgt_fen_companyId = header.companyId;

    // plcinfo, cpuinfo, source는 16진수로 출력 (Python과 일치)
    std::stringstream ss_plcinfo, ss_cpuinfo, ss_source;
    ss_plcinfo << "0x" << std::setfill('0') << std::setw(4) << std::hex << header.plcInfo;
    ss_cpuinfo << "0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(header.cpuInfo);
    ss_source << "0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(header.sourceOfFrame);

    record.xgt_fen_plcinfo = ss_plcinfo.str();
    record.xgt_fen_cpuinfo = ss_cpuinfo.str();
    record.xgt_fen_source = ss_source.str();
    record.xgt_fen_len = std::to_string(header.length);

    // fenetpos는 16진수로 출력
    std::stringstream ss_fenetpos;
    ss_fenetpos << "0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(header.fenetPosition);
    record.xgt_fen_fenetpos = ss_fenetpos.str();

    if (parse_success) {
        // cmd, dtype, errstat는 16진수로 출력
        std::stringstream ss_cmd, ss_dtype, ss_errstat;
        ss_cmd << "0x" << std::setfill('0') << std::setw(4) << std::hex << instruction.command;
        ss_dtype << "0x" << std::setfill('0') << std::setw(4) << std::hex << instruction.dataType;
        ss_errstat << "0x" << std::setfill('0') << std::setw(4) << std::hex << instruction.errorStatus;

        record.xgt_fen_cmd = ss_cmd.str();
        record.xgt_fen_dtype = ss_dtype.str();
        record.xgt_fen_blkcnt = std::to_string(instruction.blockCount);  // blkcnt는 10진수

        // Only set errstat and datasize for response packets (to match wireshark_parser)
        if (direction == "response") {
            record.xgt_fen_errstat = ss_errstat.str();
            if (instruction.dataSize > 0) {
                record.xgt_fen_datasize = std::to_string(instruction.dataSize);
            }
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

        // XGT Request-Response matching (Python: parser_common.py lines 589-605)
        uint16_t invoke_id = header.invokeId;
        if (direction == "request" && !vars_csv.empty()) {
            // Request: Store vars in state for later response matching
            std::lock_guard<std::mutex> lock(m_state_mutex);
            m_xgt_state[invoke_id] = vars_csv;
            // Do NOT add vars to request output (to match wireshark_parser)
            // But keep vars_csv for internal use (translated_addr, description)
        } else if (direction == "response" && vars_csv.empty()) {
            // Response: Look up vars from request using invoke_id
            std::lock_guard<std::mutex> lock(m_state_mutex);
            auto it = m_xgt_state.find(invoke_id);
            if (it != m_xgt_state.end()) {
                vars_csv = it->second;
                // Clean up state after use
                m_xgt_state.erase(it);
            }
        }

        // Set vars for both request and response packets (to match wireshark_parser)
        if (!vars_csv.empty()) {
            record.xgt_fen_vars = vars_csv;
        }

        // Python 로직 구현: Continuous block response를 여러 WORD로 분리 (multi-row)
        // Python: parser_common.py lines 607-665
        if (!instruction.continuousReadData.empty() &&
            instruction.continuousReadData.size() > 2 &&
            direction == "response") {

            // Continuous block 데이터를 2-byte WORD로 분리
            std::vector<uint16_t> word_values;
            for (size_t i = 0; i + 1 < instruction.continuousReadData.size(); i += 2) {
                uint16_t word = (static_cast<uint16_t>(instruction.continuousReadData[i+1]) << 8) |
                               instruction.continuousReadData[i];
                word_values.push_back(word);
            }

            // Python처럼 각 word마다 별도 row 생성 (주소 증가 포함)
            if (word_values.size() > 1) {
                // Base address 추출 (Python 로직: parser_common.py lines 632-653)
                std::string base_translated = m_assetManager.translateXgtAddress(vars_csv);
                std::string mem_type;
                int base_addr = 0;

                // Extract memory type and base address (e.g., "D523" → mem_type="D", base_addr=523)
                size_t i = 0;
                while (i < base_translated.size() && !std::isdigit(base_translated[i])) {
                    mem_type += base_translated[i];
                    i++;
                }
                if (i < base_translated.size()) {
                    base_addr = std::stoi(base_translated.substr(i));
                }

                // Create one row per word with incremented address
                for (size_t idx = 0; idx < word_values.size(); ++idx) {
                    UnifiedRecord row = record;  // Copy base record
                    row.xgt_fen_data = std::to_string(word_values[idx]);

                    // Calculate incremented address for this word
                    int incremented_addr = base_addr + static_cast<int>(idx);
                    std::string translated = mem_type + std::to_string(incremented_addr);

                    row.xgt_fen_translated_addr = translated;
                    row.xgt_fen_description = m_assetManager.getDescription(translated);

                    addUnifiedRecord(row);
                }
                return;  // Multi-row 생성 완료
            }
        }

        // Single word or non-continuous data - single row
        // Note: wireshark_parser does not output data field for response packets
        std::string data_csv;
        if (direction == "request") {
            // Only output data for request packets (to match wireshark_parser)
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
            record.xgt_fen_data = data_csv;
        }

        // Translated address 및 description (response only, Python과 일치)
        if (direction == "response" && !vars_csv.empty()) {
            std::string translatedAddr = m_assetManager.translateXgtAddress(vars_csv);
            record.xgt_fen_translated_addr = translatedAddr;
            record.xgt_fen_description = m_assetManager.getDescription(translatedAddr);
        }
    }

    addUnifiedRecord(record);
}