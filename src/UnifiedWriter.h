#ifndef UNIFIED_WRITER_H
#define UNIFIED_WRITER_H

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <mutex>
#include <ctime>
#include <functional>

// 통합 레코드 구조체 (Python 47-field CSV format)
struct UnifiedRecord {
    // 공통 필드 (14개)
    std::string timestamp;      // @timestamp
    std::string protocol;
    std::string smac;
    std::string dmac;
    std::string sip;
    std::string sp;
    std::string dip;
    std::string dp;
    std::string sq;
    std::string ak;
    std::string fl;
    std::string dir;
    std::string src_asset;      // Python: src_asset (name만)
    std::string dst_asset;      // Python: dst_asset (name만)

    // ARP (5개)
    std::string arp_op;
    std::string arp_smac;       // 추가: Python에 있음
    std::string arp_sip;        // 추가: Python에 있음
    std::string arp_tmac;
    std::string arp_tip;

    // DNS (4개)
    std::string dns_tid;
    std::string dns_fl;
    std::string dns_qc;
    std::string dns_ac;

    // DNP3 (4개)
    std::string dnp3_len;
    std::string dnp3_ctrl;
    std::string dnp3_dest;
    std::string dnp3_src;

    // Generic/Unknown (1개)
    std::string len;

    // Modbus TCP (9개) - Python과 정확히 일치
    std::string modbus_tid;
    std::string modbus_fc;
    std::string modbus_bc;
    std::string modbus_addr;
    std::string modbus_qty;
    std::string modbus_regs_addr;
    std::string modbus_regs_val;
    std::string modbus_translated_addr;
    std::string modbus_description;

    // S7Comm (7개) - Python과 정확히 일치
    std::string s7comm_ros;
    std::string s7comm_fn;
    std::string s7comm_ic;
    std::string s7comm_db;
    std::string s7comm_addr;
    std::string s7comm_len;
    std::string s7comm_description;

    // XGT FEnet (15개) - Python과 정확히 일치
    std::string xgt_fen_prid;
    std::string xgt_fen_companyId;
    std::string xgt_fen_plcinfo;
    std::string xgt_fen_cpuinfo;
    std::string xgt_fen_source;
    std::string xgt_fen_len;
    std::string xgt_fen_fenetpos;
    std::string xgt_fen_cmd;
    std::string xgt_fen_dtype;
    std::string xgt_fen_blkcnt;
    std::string xgt_fen_errstat;
    std::string xgt_fen_vars;
    std::string xgt_fen_datasize;
    std::string xgt_fen_data;
    std::string xgt_fen_translated_addr;
    std::string xgt_fen_description;
};
// Total: 59 fields - matches Python's 47-field CSV format exactly when written to CSV
// (14 common + 5 arp + 4 dns + 4 dnp3 + 1 len + 9 modbus + 7 s7comm + 15 xgt_fen)

class UnifiedWriter {
public:
    UnifiedWriter(const std::string& output_dir, int interval_minutes);
    ~UnifiedWriter();
    
    // 레코드 추가 (스레드 안전)
    void addRecord(const UnifiedRecord& record);
    
    // 파일 플러시 및 로테이션
    void flush();
    
    // 백엔드 전송 콜백 설정 (추가)
    void setBackendCallback(std::function<void(const UnifiedRecord&)> callback) {
        m_backend_callback = callback;
    }

private:
    std::string m_output_dir;
    int m_interval_minutes;
    
    // 시간 슬롯별로 레코드 저장
    std::map<std::string, std::vector<UnifiedRecord>> m_time_slots;
    std::mutex m_mutex;
    
    // 백엔드 전송 콜백 (추가)
    std::function<void(const UnifiedRecord&)> m_backend_callback;
    
    // 타임스탬프로부터 시간 슬롯 계산
    std::string getTimeSlot(const std::string& timestamp);
    
    // 시간 슬롯별 파일 작성
    void writeTimeSlot(const std::string& time_slot);
    
    // CSV/JSONL 헤더 작성
    void writeCsvHeader(std::ofstream& out);
    
    // CSV 이스케이프
    std::string escapeCSV(const std::string& s);
};

#endif // UNIFIED_WRITER_H