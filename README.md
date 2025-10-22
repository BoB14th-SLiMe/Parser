TCP Datagram Parser
libpcap/npcap을 사용하는 간단한 TCP 데이터그램 파서입니다.

빌드 방법

macOS / Linux

libpcap-dev (또는 이에 상응하는 패키지)와 cmake가 설치되어 있어야 합니다.

```
rm -rf build 
cmake -B build
cmake --build build
```


Windows (x86/x64)

CMake를 설치합니다.

Npcap SDK를 다운로드하여 설치합니다. 설치 과정에서 "SDK" 설치 옵션을 반드시 체크해야 합니다.

C++ 컴파일러를 설치합니다. (예: Visual Studio Community에서 "C++를 사용한 데스크톱 개발" 워크로드 설치)

컴파일러와 CMake의 경로가 설정된 터미널(예: "x64 Native Tools Command Prompt for VS")을 엽니다.

아래 명령어를 실행합니다:
```
rm -rf build
cmake -B build
cmake --build build
```

사용법

# macOS / Linux
```
./build/parser test_data/sample.pcap

# Windows (빌드 결과물은 build/Debug/ 폴더에 생성됩니다)

./build/Debug/parser.exe test_data/sample.pcap
```
