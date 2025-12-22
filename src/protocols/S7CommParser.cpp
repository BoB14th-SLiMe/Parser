#include "S7CommParser.h"
#include "../UnifiedWriter.h"  // ← 추가!
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <string>
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

S7CommParser::S7CommParser(AssetManager& assetManager)
    : m_assetManager(assetManager),
      m_last_cleanup(std::chrono::steady_clock::now()) {}

S7CommParser::~S7CommParser() {}

static uint16_t safe_ntohs(const u_char* ptr) {
    uint16_t val_n;
    memcpy(&val_n, ptr, 2);
    return ntohs(val_n);
}

static uint32_t s7_addr_to_int(const u_char* ptr) {
    return (ptr[0] << 16) | (ptr[1] << 8) | ptr[2];
}

std::string S7CommParser::getName() const {
    return "s7comm";
}

bool S7CommParser::isProtocol(const PacketInfo& info) const {
    // TCP port 102 check
    if (info.protocol != 6 || (info.dst_port != 102 && info.src_port != 102)) {
        return false;
    }

    // Minimum length check (TPKT 4 + COTP min 2 + S7comm 10 = 16 bytes)
    if (info.payload_size < 16) {
        return false;
    }

    // TPKT version check (RFC 1006)
    if (info.payload[0] != 0x03) {
        return false;
    }

    // TPKT reserved byte should be 0x00
    if (info.payload[1] != 0x00) {
        return false;
    }

    // COTP Length Indicator (LI field) - at byte[4]
    uint8_t cotp_hdr_len = info.payload[4];

    // S7comm PDU starts after: TPKT (4 bytes) + LI byte (1) + COTP header
    int s7_offset = 4 + 1 + cotp_hdr_len;

    // Check if S7comm PDU exists after COTP header
    if (info.payload_size < s7_offset + 10) {
        return false;
    }

    // S7comm Protocol ID check (0x32)
    if (info.payload[s7_offset] != 0x32) {
        return false;
    }

    // ROSCTR (PDU Type) check: must be 0x01-0x07
    uint8_t rosctr = info.payload[s7_offset + 1];
    if (rosctr < 0x01 || rosctr > 0x07) {
        return false;
    }

    return true;
}

void S7CommParser::parse(const PacketInfo& info) {
    // Periodic cleanup of old requests
    cleanupOldRequests();

    // Parse TPKT and COTP headers to find S7comm PDU offset
    // TPKT: 4 bytes | COTP LI: 1 byte | COTP header: variable
    uint8_t cotp_hdr_len = info.payload[4];
    int s7_offset = 4 + 1 + cotp_hdr_len;

    const u_char* s7_pdu = info.payload + s7_offset;
    int s7_pdu_len = info.payload_size - s7_offset;
    if (s7_pdu_len < 10) return;

    uint16_t pdu_ref = safe_ntohs(s7_pdu + 4);
    uint8_t rosctr = s7_pdu[1];
    uint16_t param_len = safe_ntohs(s7_pdu + 6);
    uint16_t data_len = safe_ntohs(s7_pdu + 8);
    int header_size = (rosctr == 0x01 || rosctr == 0x07) ? 10 : 12;

    bool is_request = (info.dst_port == 102);
    std::string flow_key = generateFlowKey(info, is_request);
    std::string direction;
    S7CommRequestInfo* req_info_ptr = nullptr;

    // Handle all ROSCTR types
    if (rosctr == 0x01) {
        // JOB - Request
        direction = "request";
        S7CommRequestInfo new_req;
        new_req.timestamp = std::chrono::steady_clock::now();
        new_req.pdu_ref = pdu_ref;

        if (param_len > 0 && (s7_pdu_len >= 10 + param_len)) {
            const u_char* param = s7_pdu + 10;
            new_req.function_code = param[0];
            if ((new_req.function_code == 0x04 || new_req.function_code == 0x05) && param_len >= 2) {
                uint8_t item_count = param[1];
                new_req.items.resize(item_count);
            }
        }
        m_pending_requests[flow_key][pdu_ref] = new_req;
        req_info_ptr = &m_pending_requests[flow_key][pdu_ref];
    } else if (rosctr == 0x02) {
        // ACK - Acknowledgement without data
        direction = "ack";
        if (m_pending_requests[flow_key].count(pdu_ref)) {
            req_info_ptr = &m_pending_requests[flow_key][pdu_ref];
        }
    } else if (rosctr == 0x03) {
        // ACK_DATA - Response with data
        direction = "response";
        if (m_pending_requests[flow_key].count(pdu_ref)) {
            req_info_ptr = &m_pending_requests[flow_key][pdu_ref];
        }
    } else if (rosctr == 0x07) {
        // USERDATA - Alarms, diagnostics, etc.
        direction = "userdata";
        // Userdata packets don't necessarily have matching requests
    } else {
        // Unknown ROSCTR - skip
        return;
    }

    UnifiedRecord record = createUnifiedRecord(info, direction);

    // Set len to TCP payload length (to match wireshark_parser which uses tcp.len)
    record.len = std::to_string(info.payload_size);

    // Python과 일치: s7comm.ros, s7comm.fn, s7comm.ic, s7comm.db, s7comm.addr, s7comm.len, s7comm.description
    record.s7comm_ros = std::to_string(rosctr);

    if (param_len > 0 && (s7_pdu_len >= header_size + param_len)) {
        const u_char* param = s7_pdu + header_size;
        // Format function code as hex (to match wireshark_parser)
        std::stringstream ss_fn;
        ss_fn << "0x" << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(param[0]);
        record.s7comm_fn = ss_fn.str();

        if ((param[0] == 0x04 || param[0] == 0x05) && param_len >= 2) {
            uint8_t item_count = param[1];
            record.s7comm_ic = std::to_string(item_count);

            const u_char* item_ptr = param + 2;
            for(int i = 0; i < item_count; ++i) {
                if ((item_ptr + 12) > (param + param_len)) break;

                uint8_t area = item_ptr[8];
                uint16_t db_num = 0;
                if (area == 0x84) {
                    db_num = safe_ntohs(item_ptr + 6);
                }
                uint32_t addr = s7_addr_to_int(item_ptr + 9) >> 3;

                if (i == 0) {
                    // Python과 일치: s7_syn, s7_tsz, s7_amt, s7_ar 필드 제거
                    // 로직에서 area는 사용하지만 record에 저장하지 않음
                    record.s7comm_addr = std::to_string(addr);
                    if (area == 0x84) {
                        record.s7comm_db = std::to_string(db_num);
                    }

                    // Description은 db와 addr로 계산
                    std::string translated_addr = m_assetManager.translateS7Address(
                        std::to_string(area), record.s7comm_db, record.s7comm_addr);
                    record.s7comm_description = m_assetManager.getDescription(translated_addr);
                }

                item_ptr += 12;
            }
        }
    }

    // Extract s7comm.len for response packets (to match wireshark_parser's s7comm.data field)
    // Note: wireshark's s7comm.data field is actually the item count, not the data length
    // This matches tshark output where s7comm.data == s7comm.param.itemcount
    if (rosctr == 3 && !record.s7comm_ic.empty()) {
        record.s7comm_len = record.s7comm_ic;  // Use item count as length
    }

    addUnifiedRecord(record);

    // Clean up matched request
    if (direction == "response" || direction == "ack") {
        m_pending_requests[flow_key].erase(pdu_ref);
    }
}

void S7CommParser::cleanupOldRequests() {
    auto now = std::chrono::steady_clock::now();

    // Cleanup every 60 seconds
    if (std::chrono::duration_cast<std::chrono::seconds>(now - m_last_cleanup).count() < 60) {
        return;
    }

    m_last_cleanup = now;

    // Remove requests older than 60 seconds
    for (auto it = m_pending_requests.begin(); it != m_pending_requests.end(); ) {
        auto& request_map = it->second;

        for (auto req_it = request_map.begin(); req_it != request_map.end(); ) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - req_it->second.timestamp).count() > 60) {
                req_it = request_map.erase(req_it);
            } else {
                ++req_it;
            }
        }

        // Remove empty flow entries
        if (request_map.empty()) {
            it = m_pending_requests.erase(it);
        } else {
            ++it;
        }
    }
}

std::string S7CommParser::generateFlowKey(const PacketInfo& info, bool is_request) const {
    std::string client_ip, server_ip;
    uint16_t client_port, server_port;

    if (is_request) {
        // Request: src is client, dst is server
        client_ip = info.src_ip;
        client_port = info.src_port;
        server_ip = info.dst_ip;
        server_port = info.dst_port;
    } else {
        // Response: src is server, dst is client
        server_ip = info.src_ip;
        server_port = info.src_port;
        client_ip = info.dst_ip;
        client_port = info.dst_port;
    }

    return client_ip + ":" + std::to_string(client_port) + "->" +
           server_ip + ":" + std::to_string(server_port);
}