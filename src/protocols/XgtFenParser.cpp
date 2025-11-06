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
    return "xgt-fen";
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
    if (inst_size < 4) return false;

    instruction.command = read_le<uint16_t>(inst_payload);
    instruction.dataType = read_le<uint16_t>(inst_payload + 2);
    instruction.is_continuous = (instruction.dataType == 0x0014);
    size_t offset = 4;

    bool is_response = (header.sourceOfFrame == 0x11);
    bool is_read_cmd = (instruction.command == 0x0054 || instruction.command == 0x0055);
    bool is_write_cmd = (instruction.command == 0x0058 || instruction.command == 0x0059);

    if (is_read_cmd || is_write_cmd) {
        if (inst_size < offset + 2) return false;
        instruction.reserved = read_le<uint16_t>(inst_payload + offset);
        offset += 2;

        if (is_response) {
            if (inst_size < offset + 4) return false;
            instruction.errorStatus = read_le<uint16_t>(inst_payload + offset);
            instruction.errorInfoOrBlockCount = read_le<uint16_t>(inst_payload + offset + 2);
            offset += 4;

            if (instruction.errorStatus == 0) {
                if (instruction.is_continuous) {
                    if (inst_size < offset + 2) return false;
                    instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
                    offset += 2;
                    if (inst_size < offset + instruction.dataSize) return false;
                    instruction.continuousReadData.assign(inst_payload + offset, 
                                                         inst_payload + offset + instruction.dataSize);
                    offset += instruction.dataSize;
                } else {
                    instruction.blockCount = instruction.errorInfoOrBlockCount;
                    for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                        if (inst_size < offset + 2) return false;
                        uint16_t data_len = read_le<uint16_t>(inst_payload + offset);
                        offset += 2;
                        if (inst_size < offset + data_len) return false;
                        std::vector<uint8_t> data_bytes(inst_payload + offset, 
                                                        inst_payload + offset + data_len);
                        instruction.readData.push_back({data_len, std::move(data_bytes)});
                        offset += data_len;
                    }
                }
            }
        } else {
            if (inst_size < offset + 2) return false;
            instruction.blockCount = read_le<uint16_t>(inst_payload + offset);
            offset += 2;

            if (instruction.is_continuous) {
                if (instruction.blockCount != 1) return false;
                if (inst_size < offset + 2) return false;
                uint16_t var_len = read_le<uint16_t>(inst_payload + offset);
                offset += 2;
                if (inst_size < offset + var_len) return false;
                instruction.variableName.assign(reinterpret_cast<const char*>(inst_payload + offset), var_len);
                offset += var_len;

                if (is_read_cmd) {
                    if (inst_size < offset + 2) return false;
                    instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
                    offset += 2;
                } else {
                    if (inst_size < offset + 2) return false;
                    instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
                    offset += 2;
                    if (inst_size < offset + instruction.dataSize) return false;
                    instruction.continuousReadData.assign(inst_payload + offset, 
                                                         inst_payload + offset + instruction.dataSize);
                    offset += instruction.dataSize;
                }
            } else {
                for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                    if (inst_size < offset + 2) return false;
                    uint16_t var_len = read_le<uint16_t>(inst_payload + offset);
                    offset += 2;
                    if (inst_size < offset + var_len) return false;
                    std::string var_name(reinterpret_cast<const char*>(inst_payload + offset), var_len);
                    instruction.variables.push_back({var_len, std::move(var_name)});
                    offset += var_len;
                }

                if (is_write_cmd) {
                    for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                        if (inst_size < offset + 2) return false;
                        uint16_t data_len = read_le<uint16_t>(inst_payload + offset);
                        offset += 2;
                        if (inst_size < offset + data_len) return false;
                        std::vector<uint8_t> data_bytes(inst_payload + offset, 
                                                        inst_payload + offset + data_len);
                        instruction.writeData.push_back({data_len, std::move(data_bytes)});
                        offset += data_len;
                    }
                }
            }
        }
    } else {
        return false;
    }

    return offset == inst_size;
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
    
    // XGT 공통 필드
    record.xgt_prid = std::to_string(header.invokeId);
    record.xgt_companyId = header.companyId;
    record.xgt_plcinfo = std::to_string(header.plcInfo);
    record.xgt_cpuinfo = std::to_string(header.cpuInfo);
    record.xgt_source = std::to_string(header.sourceOfFrame);
    record.xgt_len = std::to_string(header.length);
    record.xgt_fenetpos = std::to_string(header.fenetPosition);

    // JSON details 시작
    std::stringstream details_ss;
    details_ss << R"({"hdr":{"companyId":")" << header.companyId << R"(",)"
               << R"("plcInfo":)" << header.plcInfo
               << R"(,"cpuInfo":)" << (int)header.cpuInfo
               << R"(,"source":)" << (int)header.sourceOfFrame
               << R"(,"invokeId":)" << header.invokeId
               << R"(,"len":)" << header.length
               << R"(,"fenetPos":)" << (int)header.fenetPosition << "}";

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

        // JSON details
        details_ss << R"(,"inst":{"cmd":)" << instruction.command
                  << R"(,"dtype":)" << instruction.dataType
                  << R"(,"isCont":)" << (instruction.is_continuous ? "true" : "false")
                  << R"(,"blkCnt":)" << instruction.blockCount;

        if (!instruction.variables.empty()) {
            details_ss << R"(,"vars":[)";
            for(size_t i = 0; i < instruction.variables.size(); ++i) {
                if (i > 0) details_ss << ",";
                details_ss << R"(")" << instruction.variables[i].second << R"(")";
            }
            details_ss << "]";
        }
        if (!instruction.variableName.empty()) {
            details_ss << R"(,"varNm":")" << instruction.variableName << R"(")";
        }
        if (instruction.dataSize > 0) {
            details_ss << R"(,"dataSize":)" << instruction.dataSize;
        }

        if (header.sourceOfFrame == 0x11) {
            details_ss << R"(,"errStat":)" << instruction.errorStatus;
            if (instruction.errorStatus != 0) {
                details_ss << R"(,"errInfo":)" << instruction.errorInfoOrBlockCount;
            } else if (!instruction.is_continuous) {
                details_ss << R"(,"respBlkCnt":)" << instruction.errorInfoOrBlockCount;
            }
        }

        if (!instruction.readData.empty()) {
            details_ss << R"(,"readData":[)";
            for (size_t i = 0; i < instruction.readData.size(); ++i) {
                if (i > 0) details_ss << ",";
                details_ss << R"(")" << bytesToHexString(instruction.readData[i].second.data(), 
                                                         instruction.readData[i].second.size()) << R"(")";
            }
            details_ss << "]";
        }
        if (!instruction.continuousReadData.empty()) {
            std::string data_key = (header.sourceOfFrame == 0x11) ? "contRespData" : "contWriteData";
            details_ss << R"(,")" << data_key << R"(":")" 
                      << bytesToHexString(instruction.continuousReadData.data(), 
                                         instruction.continuousReadData.size()) << R"(")";
        }
        if (!instruction.writeData.empty()) {
            details_ss << R"(,"writeData":[)";
            for (size_t i = 0; i < instruction.writeData.size(); ++i) {
                if (i > 0) details_ss << ",";
                details_ss << R"(")" << bytesToHexString(instruction.writeData[i].second.data(), 
                                                         instruction.writeData[i].second.size()) << R"(")";
            }
            details_ss << "]";
        }
        details_ss << "}";
    } else {
        details_ss << R"(,"parse_error":"Instruction parsing failed","raw_instruction_hex":")"
                  << bytesToHexString(instruction_payload, instruction_size) << R"(")";
    }

    details_ss << "}";
    record.details_json = details_ss.str();
    
    addUnifiedRecord(record);
}