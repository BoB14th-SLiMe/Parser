# C++ Parser 빌드 가이드

## 📋 사전 요구사항

### 필수 도구
- **CMake**: 3.15 이상
- **GCC/G++**: 9.0 이상 또는 Clang 10.0 이상
- **Make**: GNU Make

### 필수 라이브러리
- **libpcap-dev**: 패킷 캡처
- **hiredis-dev**: Redis 클라이언트
- **librdkafka-dev**: Kafka 클라이언트
- **nlohmann-json**: JSON 처리
- **spdlog**: 로깅

---

## 🔧 환경 설정

### Ubuntu/Debian
```bash
# 필수 도구 설치
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git

# 필수 라이브러리 설치
sudo apt-get install -y \
    libpcap-dev \
    libhiredis-dev \
    librdkafka-dev \
    nlohmann-json3-dev \
    libspdlog-dev
```

### CentOS/RHEL
```bash
# 필수 도구 설치
sudo yum groupinstall "Development Tools"
sudo yum install cmake git

# 필수 라이브러리 설치
sudo yum install -y \
    libpcap-devel \
    hiredis-devel \
    librdkafka-devel
```

### macOS
```bash
# Homebrew 사용
brew install cmake
brew install libpcap
brew install hiredis
brew install librdkafka
brew install nlohmann-json
brew install spdlog
```

---

## 🚀 빌드 방법

### 1. 기본 빌드

```bash
# RealtimeParser 디렉토리로 이동
cd RealtimeParser

# build 디렉토리 생성 및 이동
mkdir -p build
cd build

# CMake 구성
cmake ..

# 빌드
make

# 결과 확인
ls -lh parser
```

### 2. 릴리스 빌드 (최적화)

```bash
cd RealtimeParser/build

# 릴리스 모드로 빌드
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 3. 디버그 빌드

```bash
cd RealtimeParser/build

# 디버그 모드로 빌드
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

---

## ✅ 빌드 확인

### 실행 파일 확인
```bash
# 파일 존재 확인
ls -lh RealtimeParser/build/parser

# 실행 권한 확인
file RealtimeParser/build/parser

# 의존성 확인
ldd RealtimeParser/build/parser
```

### 테스트 실행
```bash
cd RealtimeParser/build

# 도움말 확인
./parser --help

# 버전 확인
./parser --version

# 설정 파일로 실행
./parser --config ../config.json
```

---

## 🐛 빌드 문제 해결

### 문제 1: CMake를 찾을 수 없음

**증상**:
```
bash: cmake: command not found
```

**해결**:
```bash
# Ubuntu/Debian
sudo apt-get install cmake

# CentOS/RHEL
sudo yum install cmake

# macOS
brew install cmake
```

### 문제 2: 라이브러리를 찾을 수 없음

**증상**:
```
Could not find a package configuration file provided by "hiredis"
```

**해결**:
```bash
# Ubuntu/Debian
sudo apt-get install libhiredis-dev

# 또는 수동 설치
git clone https://github.com/redis/hiredis.git
cd hiredis
make
sudo make install
```

### 문제 3: C++ 컴파일러 버전

**증상**:
```
error: 'std::filesystem' has not been declared
```

**해결**:
```bash
# GCC 업그레이드
sudo apt-get install gcc-11 g++-11

# CMake에서 컴파일러 지정
cmake -DCMAKE_C_COMPILER=gcc-11 -DCMAKE_CXX_COMPILER=g++-11 ..
```

### 문제 4: 링킹 오류

**증상**:
```
undefined reference to `pcap_create'
```

**해결**:
```bash
# libpcap 재설치
sudo apt-get install --reinstall libpcap-dev

# 라이브러리 경로 확인
sudo ldconfig
```

---

## 🔄 재빌드

### 클린 빌드
```bash
cd RealtimeParser/build

# 빌드 파일 삭제
make clean

# 또는 전체 삭제
cd ..
rm -rf build
mkdir build
cd build

# 재빌드
cmake ..
make
```

### 특정 타겟만 빌드
```bash
# parser만 다시 빌드
make parser

# 병렬 빌드
make -j$(nproc) parser
```

---

## 📦 Docker 빌드 (권장)

### Docker를 사용한 빌드

```dockerfile
# RealtimeParser/Dockerfile.build
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential cmake \
    libpcap-dev libhiredis-dev librdkafka-dev \
    nlohmann-json3-dev libspdlog-dev

WORKDIR /build
COPY . .

RUN mkdir -p build && cd build && \
    cmake .. && \
    make -j$(nproc)

CMD ["./build/parser"]
```

### 빌드 실행
```bash
# Docker 이미지 빌드
docker build -f RealtimeParser/Dockerfile.build -t parser-builder .

# 바이너리 추출
docker create --name temp parser-builder
docker cp temp:/build/build/parser RealtimeParser/build/parser
docker rm temp
```

---

## 🎯 빌드 옵션

### CMake 옵션

```bash
# 컴파일러 최적화 레벨
cmake -DCMAKE_BUILD_TYPE=Release ..      # O3 최적화
cmake -DCMAKE_BUILD_TYPE=Debug ..        # 디버그 심볼
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .. # 최적화 + 디버그

# 특정 기능 활성화/비활성화
cmake -DENABLE_TESTS=ON ..               # 테스트 빌드
cmake -DENABLE_BENCHMARK=ON ..           # 벤치마크 빌드

# 설치 경로 지정
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
```

### Make 옵션

```bash
# 병렬 빌드 (CPU 코어 수만큼)
make -j$(nproc)

# Verbose 출력
make VERBOSE=1

# 특정 타겟
make parser
make test
make install
```

---

## 📊 빌드 결과물

```
RealtimeParser/build/
├── parser              # 실행 파일 (메인)
├── CMakeFiles/         # CMake 생성 파일
├── CMakeCache.txt      # CMake 캐시
├── Makefile            # 생성된 Makefile
└── *.o                 # 오브젝트 파일들
```

---

## 🚢 배포 준비

### 1. 바이너리 확인
```bash
# Strip (디버그 심볼 제거, 크기 감소)
strip RealtimeParser/build/parser

# 크기 확인
ls -lh RealtimeParser/build/parser
```

### 2. 의존성 확인
```bash
# 동적 라이브러리 의존성
ldd RealtimeParser/build/parser
```

### 3. Docker 이미지 빌드
```bash
# 프로젝트 루트에서
docker-compose build cpp-parser

# 이미지 확인
docker images | grep ot-security
```

---

## 💡 개발 팁

### 증분 빌드
```bash
# 변경된 파일만 다시 컴파일
cd RealtimeParser/build
make
```

### 컴파일 경고 확인
```bash
# 모든 경고 활성화
cmake -DCMAKE_CXX_FLAGS="-Wall -Wextra -Wpedantic" ..
make
```

### Static Analysis
```bash
# clang-tidy 사용
clang-tidy ../src/*.cpp -- -I../include

# cppcheck 사용
cppcheck --enable=all ../src/
```

---

## 📚 추가 자료

- [CMake 공식 문서](https://cmake.org/documentation/)
- [GCC 최적화 옵션](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- [libpcap 프로그래밍 가이드](https://www.tcpdump.org/pcap.html)
- [hiredis GitHub](https://github.com/redis/hiredis)
- [librdkafka GitHub](https://github.com/edenhill/librdkafka)
