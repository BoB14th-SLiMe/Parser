#!/bin/bash

# ============================================
# SLM 학습 데이터 생성 - Parser 실행 스크립트
# ============================================

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================
# 1. 사전 확인
# ============================================
info "=========================================="
info "SLM 학습 데이터 생성 시작"
info "=========================================="

# Parser 바이너리 확인
if [ ! -f "build/parser" ]; then
    error "Parser 바이너리가 없습니다: Parser/build/parser"
    error "먼저 빌드를 수행하세요:"
    error "  cd Parser/build"
    error "  cmake .."
    error "  make"
    exit 1
fi

info "✓ Parser 바이너리 확인: build/parser"

# 설정 파일 확인
if [ ! -f "config.json" ]; then
    error "설정 파일이 없습니다: Parser/config.json"
    exit 1
fi

info "✓ 설정 파일 확인: config.json"

# ============================================
# 2. 출력 디렉토리 생성
# ============================================
OUTPUT_DIR=${OUTPUT_DIR:-"./data/csv-output"}
mkdir -p "$OUTPUT_DIR"
mkdir -p "./logs"

info "✓ 출력 디렉토리: $OUTPUT_DIR"
info "✓ 로그 디렉토리: ./logs"

# ============================================
# 3. 실행 모드 선택
# ============================================
echo ""
info "실행 모드를 선택하세요:"
echo "  1) 실시간 캡처 (네트워크 인터페이스)"
echo "  2) PCAP 파일 분석"
echo ""
read -p "선택 (1 또는 2): " MODE

if [ "$MODE" == "1" ]; then
    # 실시간 캡처
    info "실시간 캡처 모드"
    
    # 네트워크 인터페이스 목록
    info "사용 가능한 네트워크 인터페이스:"
    ip link show | grep -E "^[0-9]+" | awk '{print "  - " $2}' | sed 's/:$//'
    echo ""
    
    read -p "인터페이스 이름 (예: eth0): " INTERFACE
    read -p "캡처 시간 (초, 0=무한): " DURATION
    
    info "인터페이스: $INTERFACE"
    info "캡처 시간: ${DURATION}초"
    
    # 실행
    info "Parser 시작..."
    sudo ./build/parser \
        --config config.json \
        --interface "$INTERFACE" \
        --duration "$DURATION" \
        --output "$OUTPUT_DIR"

elif [ "$MODE" == "2" ]; then
    # PCAP 파일 분석
    info "PCAP 파일 분석 모드"
    
    read -p "PCAP 파일 경로: " PCAP_FILE
    
    if [ ! -f "$PCAP_FILE" ]; then
        error "PCAP 파일이 존재하지 않습니다: $PCAP_FILE"
        exit 1
    fi
    
    # 레이블 입력 (선택적)
    echo ""
    info "데이터 레이블을 지정하세요 (SLM 학습용):"
    echo "  - normal: 정상 트래픽"
    echo "  - dos_attack: DoS 공격"
    echo "  - port_scan: 포트 스캔"
    echo "  - malware: 악성코드"
    echo "  - auto: 자동 레이블링"
    echo ""
    read -p "레이블 (기본: auto): " LABEL
    LABEL=${LABEL:-"auto"}
    
    info "PCAP 파일: $PCAP_FILE"
    info "레이블: $LABEL"
    
    # 실행
    info "Parser 시작..."
    ./build/parser \
        --config config.json \
        --input "$PCAP_FILE" \
        --label "$LABEL" \
        --output "$OUTPUT_DIR"
else
    error "잘못된 선택입니다."
    exit 1
fi

# ============================================
# 4. 결과 확인
# ============================================
echo ""
info "=========================================="
info "처리 완료!"
info "=========================================="

# 생성된 CSV 파일 확인
CSV_COUNT=$(ls -1 "$OUTPUT_DIR"/*.csv 2>/dev/null | wc -l)
if [ "$CSV_COUNT" -gt 0 ]; then
    info "생성된 CSV 파일: ${CSV_COUNT}개"
    echo ""
    ls -lh "$OUTPUT_DIR"/*.csv | tail -5
    echo ""
    
    # 샘플 데이터 표시
    LATEST_CSV=$(ls -t "$OUTPUT_DIR"/*.csv | head -1)
    info "최근 CSV 파일 샘플 (처음 5줄):"
    head -6 "$LATEST_CSV"
    echo ""
    
    # 통계
    TOTAL_ROWS=$(wc -l "$OUTPUT_DIR"/*.csv 2>/dev/null | tail -1 | awk '{print $1}')
    info "총 데이터 행 수: $TOTAL_ROWS"
else
    warn "생성된 CSV 파일이 없습니다."
fi

# 로그 확인
if [ -f "./logs/parser.log" ]; then
    info "로그 파일: ./logs/parser.log"
    echo ""
    info "최근 로그 (마지막 10줄):"
    tail -10 ./logs/parser.log
fi

echo ""
info "=========================================="
info "다음 단계"
info "=========================================="
echo "CSV 데이터를 사용하여 SLM 모델을 학습하세요."
echo ""
echo "Python 예시:"
echo "  import pandas as pd"
echo "  df = pd.read_csv('$OUTPUT_DIR/training_data_*.csv')"
echo "  # 모델 학습..."
echo ""
