# TFTP Client는 Python으로 작성된 파일 전송을 위한 간단한 프로토콜입니다.


# 사용된 도구 및 환경
1. Python
2. PUTTY (SSH 및 터미널 접속에 사용)

PUTTY를 통해 SSH를 이용하여 서버에 접속하고, 터미널을 통해 TFTP 클라이언트 실행했습니다.


# 프로그램 구현기능
1. TFTP 메시지 생성 및 처리
2. 중복된 블록 번호 확인 및 ACK 전송
3. 오류 처리 및 메시지 출력
4. UDP 소켓을 통한 데이터 전송 및 수신
5. 파일 읽기 및 쓰기
6. 포트 설정 기능
7. 소켓 타임아웃 설정


# 사용법
파일을 서버로 업로드(put)
python "파일명(py)" 203.250.133.88 put "업로드 할 파일명"

파일을 서버로부터 다운로드(get)
python "파일명(py)" 203.250.133.88 get "다운로드 받을 파일명"

포트 번호 설정
python "파일명(py)" 203.250.133.88 -p "포트번호" "put or get" "파일명"


# 주의사항
1. 서버로부터 파일을 가져올 때, 파일이 서버에 존재하지 않으면 프로그램이 종료됩니다.
2. 파일 전송 중 ACK를 기다리는 동안 2초의 소켓 타임아웃이 설정되어 있습니다. ACK를 받지 못하면 해당 블록에 대한 재전송이 수행됩니다.
