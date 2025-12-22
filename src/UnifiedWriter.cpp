#include "UnifiedWriter.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

UnifiedWriter::UnifiedWriter(const std::string& output_dir, int interval_minutes)
    : m_output_dir(output_dir), m_interval_minutes(interval_minutes) {
    #ifdef _WIN32
        _mkdir(m_output_dir.c_str());
    #else
        mkdir(m_output_dir.c_str(), 0755);
    #endif
    std::cout << "[INFO] UnifiedWriter initialized with " << interval_minutes << " minute intervals" << std::endl;
}

UnifiedWriter::~UnifiedWriter() {
    if (!m_time_slots.empty()) {
        std::cout << "[WARN] UnifiedWriter destroyed with unflushed data!" << std::endl;
        flush();
    }
}

std::string UnifiedWriter::getTimeSlot(const std::string& timestamp) {
    // time_interval이 0이면 "all" 슬롯 사용
    if (m_interval_minutes == 0) {
        return "output_all";
    }
    
    // timestamp 형식: 2023-05-10T02:24:15.123456Z
    if (timestamp.length() < 19) {
        std::cout << "[WARN] Invalid timestamp format: " << timestamp << std::endl;
        return "";
    }
    
    struct tm tm_time = {};
    std::string ts = timestamp.substr(0, 19);
    
    // 파싱
    sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%d",
           &tm_time.tm_year, &tm_time.tm_mon, &tm_time.tm_mday,
           &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec);
    
    tm_time.tm_year -= 1900;
    tm_time.tm_mon -= 1;
    
    // 분을 interval 단위로 내림
    int slot_minute = (tm_time.tm_min / m_interval_minutes) * m_interval_minutes;
    tm_time.tm_min = slot_minute;
    tm_time.tm_sec = 0;
    
    // 출력 형식: output_20230510_0224
    std::stringstream ss;
    ss << "output_"
       << std::setfill('0') << std::setw(4) << (tm_time.tm_year + 1900)
       << std::setfill('0') << std::setw(2) << (tm_time.tm_mon + 1)
       << std::setfill('0') << std::setw(2) << tm_time.tm_mday
       << "_"
       << std::setfill('0') << std::setw(2) << tm_time.tm_hour
       << std::setfill('0') << std::setw(2) << slot_minute;
    
    return ss.str();
}

std::string UnifiedWriter::escapeCSV(const std::string& s) {
    if (s.empty()) return "";
    if (s.find_first_of(",\"\n") == std::string::npos) {
        return s;
    }
    std::string result = "\"";
    for (char c : s) {
        if (c == '"') {
            result += "\"\"";
        } else {
            result += c;
        }
    }
    result += "\"";
    return result;
}

void UnifiedWriter::addRecord(const UnifiedRecord& record) {
    std::string time_slot = getTimeSlot(record.timestamp);
    
    if (!time_slot.empty()) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_time_slots[time_slot].push_back(record);
        
        // 백엔드로 전송 (추가)
        if (m_backend_callback) {
            m_backend_callback(record);
        }
    }
}

void UnifiedWriter::writeCsvHeader(std::ofstream& out) {
    // Python parser_common.py CSV_HEADERS (47 fields) - 정확히 일치
    out << "@timestamp,protocol,smac,dmac,sip,sp,dip,dp,sq,ak,fl,dir,"
        << "src_asset,dst_asset,"
        << "arp.op,arp.smac,arp.sip,arp.tmac,arp.tip,"
        << "dns.tid,dns.fl,dns.qc,dns.ac,"
        << "dnp3.len,dnp3.ctrl,dnp3.dest,dnp3.src,"
        << "len,"
        << "modbus.tid,modbus.fc,modbus.bc,modbus.addr,modbus.qty,"
        << "modbus.regs.addr,modbus.regs.val,"
        << "modbus.translated_addr,modbus.description,"
        << "s7comm.ros,s7comm.fn,s7comm.ic,s7comm.db,s7comm.addr,"
        << "s7comm.len,s7comm.description,"
        << "xgt_fen.prid,xgt_fen.companyId,xgt_fen.plcinfo,xgt_fen.cpuinfo,"
        << "xgt_fen.source,xgt_fen.len,xgt_fen.fenetpos,xgt_fen.cmd,"
        << "xgt_fen.dtype,xgt_fen.blkcnt,xgt_fen.errstat,"
        << "xgt_fen.vars,xgt_fen.datasize,xgt_fen.data,"
        << "xgt_fen.translated_addr,xgt_fen.description\n";
}

void UnifiedWriter::writeTimeSlot(const std::string& time_slot) {
    if (m_time_slots[time_slot].empty()) {
        return;
    }
    
    std::vector<UnifiedRecord>& records = m_time_slots[time_slot];
    // Use stable_sort to preserve insertion order for records with the same timestamp
    // This is critical for Modbus responses where multiple register records share the same timestamp
    std::stable_sort(records.begin(), records.end(),
        [](const UnifiedRecord& a, const UnifiedRecord& b) {
            return a.timestamp < b.timestamp;
        });
    
    // CSV 파일
    std::string csv_filepath = m_output_dir + "/" + time_slot + ".csv";
    std::ofstream csv_out(csv_filepath);
    
    if (!csv_out.is_open()) {
        std::cerr << "[ERROR] Could not open CSV file " << csv_filepath << std::endl;
        return;
    }
    
    writeCsvHeader(csv_out);
    
    // JSONL 파일
    std::string jsonl_filepath = m_output_dir + "/" + time_slot + ".jsonl";
    std::ofstream jsonl_out(jsonl_filepath);
    
    if (!jsonl_out.is_open()) {
        std::cerr << "[ERROR] Could not open JSONL file " << jsonl_filepath << std::endl;
        csv_out.close();
        return;
    }
    
    std::cout << "[INFO] Writing time slot: " << time_slot << " with " << records.size() << " records" << std::endl;
    
    for (const auto& record : records) {
        // CSV 작성 - Python 47-field CSV format과 정확히 일치
        csv_out << escapeCSV(record.timestamp) << ","
                << escapeCSV(record.protocol) << ","
                << escapeCSV(record.smac) << ","
                << escapeCSV(record.dmac) << ","
                << escapeCSV(record.sip) << ","
                << escapeCSV(record.sp) << ","
                << escapeCSV(record.dip) << ","
                << escapeCSV(record.dp) << ","
                << escapeCSV(record.sq) << ","
                << escapeCSV(record.ak) << ","
                << escapeCSV(record.fl) << ","
                << escapeCSV(record.dir) << ","
                << escapeCSV(record.src_asset) << ","
                << escapeCSV(record.dst_asset) << ","
                << escapeCSV(record.arp_op) << ","
                << escapeCSV(record.arp_smac) << ","
                << escapeCSV(record.arp_sip) << ","
                << escapeCSV(record.arp_tmac) << ","
                << escapeCSV(record.arp_tip) << ","
                << escapeCSV(record.dns_tid) << ","
                << escapeCSV(record.dns_fl) << ","
                << escapeCSV(record.dns_qc) << ","
                << escapeCSV(record.dns_ac) << ","
                << escapeCSV(record.dnp3_len) << ","
                << escapeCSV(record.dnp3_ctrl) << ","
                << escapeCSV(record.dnp3_dest) << ","
                << escapeCSV(record.dnp3_src) << ","
                << escapeCSV(record.len) << ","
                << escapeCSV(record.modbus_tid) << ","
                << escapeCSV(record.modbus_fc) << ","
                << escapeCSV(record.modbus_bc) << ","
                << escapeCSV(record.modbus_addr) << ","
                << escapeCSV(record.modbus_qty) << ","
                << escapeCSV(record.modbus_regs_addr) << ","
                << escapeCSV(record.modbus_regs_val) << ","
                << escapeCSV(record.modbus_translated_addr) << ","
                << escapeCSV(record.modbus_description) << ","
                << escapeCSV(record.s7comm_ros) << ","
                << escapeCSV(record.s7comm_fn) << ","
                << escapeCSV(record.s7comm_ic) << ","
                << escapeCSV(record.s7comm_db) << ","
                << escapeCSV(record.s7comm_addr) << ","
                << escapeCSV(record.s7comm_len) << ","
                << escapeCSV(record.s7comm_description) << ","
                << escapeCSV(record.xgt_fen_prid) << ","
                << escapeCSV(record.xgt_fen_companyId) << ","
                << escapeCSV(record.xgt_fen_plcinfo) << ","
                << escapeCSV(record.xgt_fen_cpuinfo) << ","
                << escapeCSV(record.xgt_fen_source) << ","
                << escapeCSV(record.xgt_fen_len) << ","
                << escapeCSV(record.xgt_fen_fenetpos) << ","
                << escapeCSV(record.xgt_fen_cmd) << ","
                << escapeCSV(record.xgt_fen_dtype) << ","
                << escapeCSV(record.xgt_fen_blkcnt) << ","
                << escapeCSV(record.xgt_fen_errstat) << ","
                << escapeCSV(record.xgt_fen_vars) << ","
                << escapeCSV(record.xgt_fen_datasize) << ","
                << escapeCSV(record.xgt_fen_data) << ","
                << escapeCSV(record.xgt_fen_translated_addr) << ","
                << escapeCSV(record.xgt_fen_description) << "\n";
        
        // ===== JSONL 작성 - 수정된 부분 =====
        std::stringstream json_ss;
        json_ss << R"({"@timestamp":")" << record.timestamp << R"(",)"
                << R"("protocol":")" << record.protocol << R"(",)"
                << R"("smac":")" << record.smac << R"(",)"
                << R"("dmac":")" << record.dmac << R"(",)"
                << R"("sip":")" << record.sip << R"(",)"
                << R"("dip":")" << record.dip << R"(",)";

        if (!record.sp.empty()) json_ss << R"("sp":)" << record.sp << R"(,)";
        if (!record.dp.empty()) json_ss << R"("dp":)" << record.dp << R"(,)";
        if (!record.sq.empty()) json_ss << R"("sq":)" << record.sq << R"(,)";
        if (!record.ak.empty()) json_ss << R"("ak":)" << record.ak << R"(,)";
        if (!record.fl.empty()) json_ss << R"("fl":)" << record.fl << R"(,)";
        if (!record.dir.empty()) json_ss << R"("dir":")" << record.dir << R"(",)";

        // ===== len 필드 추가 (모든 프로토콜에 공통) =====
        if (!record.len.empty()) {
            json_ss << R"("len":)" << record.len << R"(,)";
        }

        // 자산 정보
        if (!record.src_asset.empty()) {
            json_ss << R"("src_asset":")" << record.src_asset << R"(",)";
        }
        if (!record.dst_asset.empty()) {
            json_ss << R"("dst_asset":")" << record.dst_asset << R"(",)";
        }

        // 프로토콜별 상세 정보 - Python과 정확히 일치
        if (record.protocol == "arp") {
            if (!record.arp_op.empty()) json_ss << R"("arp.op":")" << record.arp_op << R"(",)";
            if (!record.arp_smac.empty()) json_ss << R"("arp.smac":")" << record.arp_smac << R"(",)";
            if (!record.arp_sip.empty()) json_ss << R"("arp.sip":")" << record.arp_sip << R"(",)";
            if (!record.arp_tmac.empty()) json_ss << R"("arp.tmac":")" << record.arp_tmac << R"(",)";
            if (!record.arp_tip.empty()) json_ss << R"("arp.tip":")" << record.arp_tip << R"(",)";
        } else if (record.protocol == "dns") {
            if (!record.dns_tid.empty()) json_ss << R"("dns.tid":)" << record.dns_tid << ",";
            if (!record.dns_fl.empty()) json_ss << R"("dns.fl":)" << record.dns_fl << ",";
            if (!record.dns_qc.empty()) json_ss << R"("dns.qc":)" << record.dns_qc << ",";
            if (!record.dns_ac.empty()) json_ss << R"("dns.ac":)" << record.dns_ac << ",";
        } else if (record.protocol == "dnp3") {
            if (!record.dnp3_len.empty()) json_ss << R"("dnp3.len":)" << record.dnp3_len << ",";
            if (!record.dnp3_ctrl.empty()) json_ss << R"("dnp3.ctrl":)" << record.dnp3_ctrl << ",";
            if (!record.dnp3_dest.empty()) json_ss << R"("dnp3.dest":)" << record.dnp3_dest << ",";
            if (!record.dnp3_src.empty()) json_ss << R"("dnp3.src":)" << record.dnp3_src << ",";
        } else if (record.protocol == "modbus") {
            if (!record.modbus_tid.empty()) json_ss << R"("modbus.tid":)" << record.modbus_tid << ",";
            if (!record.modbus_fc.empty()) json_ss << R"("modbus.fc":)" << record.modbus_fc << ",";
            if (!record.modbus_bc.empty()) json_ss << R"("modbus.bc":)" << record.modbus_bc << ",";
            if (!record.modbus_addr.empty()) json_ss << R"("modbus.addr":)" << record.modbus_addr << ",";
            if (!record.modbus_qty.empty()) json_ss << R"("modbus.qty":)" << record.modbus_qty << ",";
            if (!record.modbus_regs_addr.empty()) json_ss << R"("modbus.regs.addr":)" << record.modbus_regs_addr << ",";
            if (!record.modbus_regs_val.empty()) json_ss << R"("modbus.regs.val":)" << record.modbus_regs_val << ",";
            if (!record.modbus_translated_addr.empty()) json_ss << R"("modbus.translated_addr":")" << record.modbus_translated_addr << R"(",)";
            if (!record.modbus_description.empty()) json_ss << R"("modbus.description":")" << record.modbus_description << R"(",)";
        } else if (record.protocol == "s7comm") {
            if (!record.s7comm_ros.empty()) json_ss << R"("s7comm.ros":)" << record.s7comm_ros << ",";
            if (!record.s7comm_fn.empty()) json_ss << R"("s7comm.fn":)" << record.s7comm_fn << ",";
            if (!record.s7comm_ic.empty()) json_ss << R"("s7comm.ic":)" << record.s7comm_ic << ",";
            if (!record.s7comm_db.empty()) json_ss << R"("s7comm.db":)" << record.s7comm_db << ",";
            if (!record.s7comm_addr.empty()) json_ss << R"("s7comm.addr":)" << record.s7comm_addr << ",";
            if (!record.s7comm_len.empty()) json_ss << R"("s7comm.len":)" << record.s7comm_len << ",";
            if (!record.s7comm_description.empty()) json_ss << R"("s7comm.description":")" << record.s7comm_description << R"(",)";
        } else if (record.protocol == "xgt_fen") {
            if (!record.xgt_fen_prid.empty()) json_ss << R"("xgt_fen.prid":)" << record.xgt_fen_prid << ",";
            if (!record.xgt_fen_companyId.empty()) json_ss << R"("xgt_fen.companyId":")" << record.xgt_fen_companyId << R"(",)";
            if (!record.xgt_fen_plcinfo.empty()) json_ss << R"("xgt_fen.plcinfo":)" << record.xgt_fen_plcinfo << ",";
            if (!record.xgt_fen_cpuinfo.empty()) json_ss << R"("xgt_fen.cpuinfo":)" << record.xgt_fen_cpuinfo << ",";
            if (!record.xgt_fen_source.empty()) json_ss << R"("xgt_fen.source":)" << record.xgt_fen_source << ",";
            if (!record.xgt_fen_len.empty()) json_ss << R"("xgt_fen.len":)" << record.xgt_fen_len << ",";
            if (!record.xgt_fen_fenetpos.empty()) json_ss << R"("xgt_fen.fenetpos":)" << record.xgt_fen_fenetpos << ",";
            if (!record.xgt_fen_cmd.empty()) json_ss << R"("xgt_fen.cmd":)" << record.xgt_fen_cmd << ",";
            if (!record.xgt_fen_dtype.empty()) json_ss << R"("xgt_fen.dtype":)" << record.xgt_fen_dtype << ",";
            if (!record.xgt_fen_blkcnt.empty()) json_ss << R"("xgt_fen.blkcnt":)" << record.xgt_fen_blkcnt << ",";
            if (!record.xgt_fen_errstat.empty()) json_ss << R"("xgt_fen.errstat":)" << record.xgt_fen_errstat << ",";
            if (!record.xgt_fen_vars.empty()) json_ss << R"("xgt_fen.vars":")" << record.xgt_fen_vars << R"(",)";
            if (!record.xgt_fen_datasize.empty()) json_ss << R"("xgt_fen.datasize":)" << record.xgt_fen_datasize << ",";
            if (!record.xgt_fen_data.empty()) json_ss << R"("xgt_fen.data":")" << record.xgt_fen_data << R"(",)";
            if (!record.xgt_fen_translated_addr.empty()) json_ss << R"("xgt_fen.translated_addr":")" << record.xgt_fen_translated_addr << R"(",)";
            if (!record.xgt_fen_description.empty()) json_ss << R"("xgt_fen.description":")" << record.xgt_fen_description << R"(",)";
        }
        // ===== 프로토콜별 조건문 삭제: else if (!record.len.empty()) { ... } =====
        // len 필드는 이미 위에서 공통적으로 처리됨

        // 마지막 콤마 제거 후 파일에 쓰기
        std::string json_line = json_ss.str();
        if (!json_line.empty() && json_line.back() == ',') {
            json_line.pop_back();
        }
        json_line += "}\n";
        jsonl_out << json_line;
    }
    
    csv_out.close();
    jsonl_out.close();
    
    std::cout << "[SUCCESS] Written " << records.size() << " records to " << time_slot << std::endl;
}

void UnifiedWriter::flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_time_slots.empty()) {
        std::cout << "[INFO] No data to flush" << std::endl;
        return;
    }
    
    std::cout << "[INFO] Flushing UnifiedWriter - " << m_time_slots.size() << " time slots" << std::endl;
    
    for (const auto& slot : m_time_slots) {
        writeTimeSlot(slot.first);
    }
    
    m_time_slots.clear();
    std::cout << "[INFO] Flush complete" << std::endl;
}