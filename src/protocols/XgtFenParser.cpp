#include "XgtFenParser.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <cstring> // For memcpy
#include <algorithm> // for std::copy
#include "nlohmann/json.hpp"
#include "../network/network_headers.h" // For ntohs/htons (endian conversion) - use portable versions if needed


// Helper function implementation to read little-endian values
template <typename T>
T read_le(const u_char* buffer) {
    T value;
    memcpy(&value, buffer, sizeof(T));
    // Assuming the system is little-endian. If the system were big-endian,
    // byte swapping would be needed here. For simplicity, we assume LE.
    // Portable version would use bit shifts.
#ifdef __GNUC__ // Or other checks for endianness if needed
    // if (system_is_big_endian) { swap_bytes(&value); }
#endif
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


// 생성자
XgtFenParser::XgtFenParser(AssetManager& assetManager)
    : m_assetManager(assetManager) {}

// 소멸자
XgtFenParser::~XgtFenParser() {}

// 프로토콜 이름 반환
std::string XgtFenParser::getName() const {
    return "xgt-fen";
}

// 프로토콜 식별
bool XgtFenParser::isProtocol(const PacketInfo& info) const {
    // XGT FEN uses TCP port 2004
    // Check minimum header size and Company ID "LSIS-XGT"
    return info.protocol == IPPROTO_TCP &&
           (info.dst_port == 2004 || info.src_port == 2004) &&
           info.payload_size >= 20 && // Minimum Application Header size
           memcmp(info.payload, "LSIS-XGT", 8) == 0;
}

// CSV 헤더 작성
void XgtFenParser::writeCsvHeader(std::ofstream& csv_stream) {
    // Add more specific fields extracted from the protocol
    csv_stream << "@timestamp,smac,dmac,sip,sp,dip,dp,prid,dir,"
               << "hdr.companyId,hdr.plcinfo,hdr.cpuinfo,hdr.source,hdr.len,hdr.fenetpos,"
               << "inst.cmd,inst.dtype,inst.blkcnt,inst.errstat,inst.errinfo,"
               << "inst.vars,inst.datasize,inst.data," // Combined fields for simplicity in basic CSV
               << "translated_addr,description\n";
}

// Header 파싱 헬퍼 함수
bool XgtFenParser::parseHeader(const u_char* payload, size_t size, XgtFenHeader& header) {
    if (size < 20) return false;

    header.companyId.assign(reinterpret_cast<const char*>(payload), 8);
    header.reserved1 = read_le<uint16_t>(payload + 8);
    header.plcInfo = read_le<uint16_t>(payload + 10);
    header.cpuInfo = payload[12];
    header.sourceOfFrame = payload[13];
    header.invokeId = read_le<uint16_t>(payload + 14);
    header.length = read_le<uint16_t>(payload + 16); // Instruction length
    header.fenetPosition = payload[18];
    header.reserved2 = payload[19]; // BCC/Reserved

    // Basic validation
    if (header.companyId != "LSIS-XGT") return false;

    return true;
}

// Instruction 파싱 헬퍼 함수
bool XgtFenParser::parseInstruction(const u_char* inst_payload, size_t inst_size, const XgtFenHeader& header, XgtFenInstruction& instruction) {
    if (inst_size < 4) return false; // Minimum size for command + data type

    instruction.command = read_le<uint16_t>(inst_payload);
    instruction.dataType = read_le<uint16_t>(inst_payload + 2);
    instruction.is_continuous = (instruction.dataType == 0x0014); // <<< Set the flag here
    size_t offset = 4;

    bool is_response = (header.sourceOfFrame == 0x11);
    bool is_read_cmd = (instruction.command == 0x0054 || instruction.command == 0x0055); // Read Req/Resp
    bool is_write_cmd = (instruction.command == 0x0058 || instruction.command == 0x0059); // Write Req/Resp
    // bool is_continuous = (instruction.dataType == 0x0014); // <<< Removed local variable

    if (is_read_cmd || is_write_cmd) {
        if (inst_size < offset + 2) return false; // Reserved field
        instruction.reserved = read_le<uint16_t>(inst_payload + offset);
        offset += 2;

        if (is_response) {
            // Responses have Error Status and Error Info/Block Count
            if (inst_size < offset + 4) return false;
            instruction.errorStatus = read_le<uint16_t>(inst_payload + offset);
            instruction.errorInfoOrBlockCount = read_le<uint16_t>(inst_payload + offset + 2);
            offset += 4;

            if (instruction.errorStatus == 0) { // Success
                if (instruction.is_continuous) { // <<< Use struct member
                    if (inst_size < offset + 2) return false; // Data size
                    instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
                    offset += 2;
                    if (inst_size < offset + instruction.dataSize) return false; // Data itself
                    instruction.continuousReadData.assign(inst_payload + offset, inst_payload + offset + instruction.dataSize);
                    offset += instruction.dataSize;
                } else { // Individual read response
                    instruction.blockCount = instruction.errorInfoOrBlockCount; // Reinterpret this field
                    for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                         if (inst_size < offset + 2) return false; // Data Size
                         uint16_t data_len = read_le<uint16_t>(inst_payload + offset);
                         offset += 2;
                         if (inst_size < offset + data_len) return false; // Data
                         std::vector<uint8_t> data_bytes(inst_payload + offset, inst_payload + offset + data_len);
                         instruction.readData.push_back({data_len, std::move(data_bytes)});
                         offset += data_len;
                    }
                }
            } // Error responses don't contain data after error fields
        } else { // Requests
            if (inst_size < offset + 2) return false; // Block Count
            instruction.blockCount = read_le<uint16_t>(inst_payload + offset);
            offset += 2;

            if (instruction.is_continuous) { // <<< Use struct member
                if (instruction.blockCount != 1) return false; // Continuous requests have 1 block
                if (inst_size < offset + 2) return false; // Var Length
                uint16_t var_len = read_le<uint16_t>(inst_payload + offset);
                offset += 2;
                if (inst_size < offset + var_len) return false; // Var Name
                instruction.variableName.assign(reinterpret_cast<const char*>(inst_payload + offset), var_len);
                offset += var_len;

                if (is_read_cmd) { // Continuous Read Request
                     if (inst_size < offset + 2) return false; // Data Size
                     instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
                     offset += 2;
                } else { // Continuous Write Request
                     if (inst_size < offset + 2) return false; // Data Size
                     instruction.dataSize = read_le<uint16_t>(inst_payload + offset);
                     offset += 2;
                     if (inst_size < offset + instruction.dataSize) return false; // Data
                     instruction.continuousReadData.assign(inst_payload + offset, inst_payload + offset + instruction.dataSize); // Re-use continuousReadData for write data
                     offset += instruction.dataSize;
                }

            } else { // Individual Requests
                // Parse Variables first
                 for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                     if (inst_size < offset + 2) return false; // Var Length
                     uint16_t var_len = read_le<uint16_t>(inst_payload + offset);
                     offset += 2;
                     if (inst_size < offset + var_len) return false; // Var Name
                     std::string var_name(reinterpret_cast<const char*>(inst_payload + offset), var_len);
                     instruction.variables.push_back({var_len, std::move(var_name)});
                     offset += var_len;
                 }

                 if (is_write_cmd) { // Individual Write Request - parse data after variables
                     for (uint16_t i = 0; i < instruction.blockCount; ++i) {
                         if (inst_size < offset + 2) return false; // Data Length
                         uint16_t data_len = read_le<uint16_t>(inst_payload + offset);
                         offset += 2;
                         if (inst_size < offset + data_len) return false; // Data
                         std::vector<uint8_t> data_bytes(inst_payload + offset, inst_payload + offset + data_len);
                         instruction.writeData.push_back({data_len, std::move(data_bytes)});
                         offset += data_len;
                     }
                 } // Individual Read request only has variables
            }
        }
    } else {
        // Unknown command
        return false;
    }

    // Check if we parsed exactly the expected number of bytes
    return offset == inst_size;
}


// 패킷 파싱
void XgtFenParser::parse(const PacketInfo& info) {
    XgtFenHeader header;
    if (!parseHeader(info.payload, info.payload_size, header)) {
        // Handle header parsing error - maybe log or write a generic error entry
         std::cerr << "XGT FEN Header Parse Error. Timestamp: " << info.timestamp << std::endl;
        return;
    }

    // Check if instruction length matches payload size
    if (20 + header.length != info.payload_size) {
        std::cerr << "XGT FEN Size Mismatch. Header len: " << header.length
                  << ", Actual inst size: " << (info.payload_size - 20)
                  << ". Timestamp: " << info.timestamp << std::endl;
        // Proceed with caution or return, depending on desired strictness
        // return;
    }

    XgtFenInstruction instruction = {}; // Initialize instruction struct
    const u_char* instruction_payload = info.payload + 20;
    // Use the minimum of the declared length and the actual available size
    // <<< FIX HERE: Cast the result of the ternary operator to size_t >>>
    size_t instruction_size = std::min(static_cast<size_t>(header.length),
                                       static_cast<size_t>(info.payload_size > 20 ? info.payload_size - 20 : 0));


    bool parse_success = parseInstruction(instruction_payload, instruction_size, header, instruction);

    // Prepare JSON output
    nlohmann::json details_json;
    details_json["hdr"]["companyId"] = header.companyId;
    // details_json["hdr"]["reserved1"] = header.reserved1; // Often 0, maybe omit
    details_json["hdr"]["plcInfo"] = header.plcInfo;
    details_json["hdr"]["cpuInfo"] = header.cpuInfo;
    details_json["hdr"]["source"] = header.sourceOfFrame;
    details_json["hdr"]["invokeId"] = header.invokeId;
    details_json["hdr"]["len"] = header.length;
    details_json["hdr"]["fenetPos"] = header.fenetPosition;
    // details_json["hdr"]["reserved2"] = header.reserved2; // Often 0, maybe omit

    if (parse_success) {
        details_json["inst"]["cmd"] = instruction.command;
        details_json["inst"]["dtype"] = instruction.dataType;
        details_json["inst"]["isCont"] = instruction.is_continuous; // Add continuous flag to JSON if needed
        // details_json["inst"]["reserved"] = instruction.reserved; // Often 0
        details_json["inst"]["blkCnt"] = instruction.blockCount; // Mostly relevant for requests

        if (!instruction.variables.empty()) {
            details_json["inst"]["vars"] = nlohmann::json::array();
            for(const auto& var : instruction.variables) {
                details_json["inst"]["vars"].push_back(var.second);
            }
        }
        if (!instruction.variableName.empty()) {
             details_json["inst"]["varNm"] = instruction.variableName;
        }
        if (instruction.dataSize > 0) { // Relevant for cont. read req and responses
             details_json["inst"]["dataSize"] = instruction.dataSize;
        }

        // Response specific fields
        if (header.sourceOfFrame == 0x11) { // Only responses have error status
             details_json["inst"]["errStat"] = instruction.errorStatus;
             if (instruction.errorStatus != 0) { // Error occurred
                details_json["inst"]["errInfo"] = instruction.errorInfoOrBlockCount;
             } else if (!instruction.is_continuous) { // Normal Individual Read Response
                // errorInfoOrBlockCount is blockCount for successful read response
                details_json["inst"]["respBlkCnt"] = instruction.errorInfoOrBlockCount;
             }
             // For successful continuous read response, errorInfoOrBlockCount is 1 (block count)
             // but we don't necessarily need to add it to json
        }


        if (!instruction.readData.empty()) {
             details_json["inst"]["readData"] = nlohmann::json::array();
             for (const auto& data_pair : instruction.readData) {
                  details_json["inst"]["readData"].push_back(bytesToHexString(data_pair.second.data(), data_pair.second.size()));
             }
        }
        if (!instruction.continuousReadData.empty()) {
             // Use "contRespData" for read response, "contWriteData" for write request
             std::string data_key = (header.sourceOfFrame == 0x11) ? "contRespData" : "contWriteData";
             details_json["inst"][data_key] = bytesToHexString(instruction.continuousReadData.data(), instruction.continuousReadData.size());
        }
         if (!instruction.writeData.empty()) {
             details_json["inst"]["writeData"] = nlohmann::json::array();
             for (const auto& data_pair : instruction.writeData) {
                  details_json["inst"]["writeData"].push_back(bytesToHexString(data_pair.second.data(), data_pair.second.size()));
             }
        }
    } else {
        details_json["parse_error"] = "Instruction parsing failed";
        // Include raw instruction hex for debugging
        details_json["raw_instruction_hex"] = bytesToHexString(instruction_payload, instruction_size);
    }

    std::string details_str = details_json.dump();
    std::string direction = (header.sourceOfFrame == 0x33) ? "request" : (header.sourceOfFrame == 0x11 ? "response" : "unknown");

    // Attempt to find the primary variable name for translation
    std::string primary_var_name;
    if (!instruction.variableName.empty()) {
        primary_var_name = instruction.variableName;
    } else if (!instruction.variables.empty()) {
        primary_var_name = instruction.variables[0].second; // Use the first variable name
    }

    std::string translatedAddr = m_assetManager.translateXgtAddress(primary_var_name);
    std::string description = m_assetManager.getDescription(translatedAddr);


    // JSONL 라인 작성
    writeJsonl(info, direction, details_str);

    // CSV 라인 작성
    if (m_csv_stream && m_csv_stream->is_open()) {
        *m_csv_stream << info.timestamp << ","
                      << info.src_mac << "," << info.dst_mac << ","
                      << info.src_ip << "," << info.src_port << ","
                      << info.dst_ip << "," << info.dst_port << ","
                      << header.invokeId << "," // Use invokeId as prid
                      << direction << ","

                      // Header fields
                      << escape_csv(header.companyId) << ","
                      << header.plcInfo << "," << (int)header.cpuInfo << "," << (int)header.sourceOfFrame << ","
                      << header.length << "," << (int)header.fenetPosition << ","

                      // Instruction fields (simplified for single line CSV)
                      << instruction.command << "," << instruction.dataType << ","
                      << instruction.blockCount << "," << instruction.errorStatus << ","
                      << instruction.errorInfoOrBlockCount << ",";

                      // Combine variable names for CSV
                      std::string vars_csv;
                      if (!instruction.variableName.empty()) {
                          vars_csv = instruction.variableName;
                      } else {
                          for(size_t i = 0; i < instruction.variables.size(); ++i) {
                              vars_csv += instruction.variables[i].second;
                              if (i < instruction.variables.size() - 1) vars_csv += ";";
                          }
                      }
                      *m_csv_stream << escape_csv(vars_csv) << ","
                      << instruction.dataSize << ",";

                      // Combine data for CSV (show continuous or first item of individual)
                      std::string data_csv;
                      if (!instruction.continuousReadData.empty()) {
                          data_csv = bytesToHexString(instruction.continuousReadData.data(), instruction.continuousReadData.size());
                      } else if (!instruction.readData.empty()) {
                           data_csv = bytesToHexString(instruction.readData[0].second.data(), instruction.readData[0].second.size());
                           if(instruction.readData.size() > 1) data_csv += "...(" + std::to_string(instruction.readData.size()) + " items)";
                      } else if (!instruction.writeData.empty()) {
                           data_csv = bytesToHexString(instruction.writeData[0].second.data(), instruction.writeData[0].second.size());
                           if(instruction.writeData.size() > 1) data_csv += "...(" + std::to_string(instruction.writeData.size()) + " items)";
                      }
                       *m_csv_stream << data_csv << "," // Simplified data output


                      << escape_csv(translatedAddr) << ","
                      << escape_csv(description) << "\n";
    }
}

