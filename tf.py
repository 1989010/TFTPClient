#!/usr/bin/python3
'''
$ tftp ip_address [-p port_number] <get|put> filename
'''
import socket                   # 소켓 라이브러리
import argparse                 # 명령행 인수 파싱을 위한 라이브러리
from struct import pack         # 데이터 패킹을 위한 라이브러리

DEFAULT_PORT = 69                   # TFTP에서 사용되는 기본 포트번호 69
BLOCK_SIZE = 512                    # 데이터 블록 크기, 한 번에 전송되는 파일 크기
DEFAULT_TRANSFER_MODE = 'octet'     # 전송 모드 : 'octet'모드 = 8비트 이진 모드

OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}    # TFTP 메시지에서 사용되는 OPCODE 값
MODE = {'netascii': 1, 'octet': 2, 'mail': 3}                     # TFTP 전송 모드를 나타냄

# TFTP 에러 코드
ERROR_CODE = {
    0: "Not defined, see error message (if any).",     # 정의되지 않았다.
    1: "File not found.",                              # 파일을 찾을 수 없다.
    2: "Access violation.",                            # 접근 권한이 없다.
    3: "Disk full or allocation exceeded.",            # 디스크가 가득 찼거나 할당이 초과 되었다.
    4: "Illegal TFTP operation.",                      # 잘못된 TFTP 작업이다.
    5: "Unknown transfer ID.",                         # 알 수 없는 전송 ID이다.
    6: "File already exists.",                         # 파일이 이미 존재한다.
    7: "No such user."                                 # 해당 사용자를 찾을 수 없다.
}

def send_wrq(filename, mode):      # 패킷의 형식을 지정하는 문자열 (wrq 전송모드)
    format_str = f'>h{len(filename)}sB{len(mode)}sB'           # 패킷 데이터를 생성, 해당 데이터를 소켓을 통해 서버 주소로 전송
    wrq_message = pack(format_str, OPCODE['WRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)   #TFTP Write Request 메시지를 생성하고 패킹
    sock.sendto(wrq_message, server_address)                   # 생성된 wrq 메시지를 서버 주소로 전송
    print(wrq_message)                                         # 생성된 wrq 메시지 출력

def send_rrq(filename, mode):      # 패킷의 형식을 지정하는 문자열 (rrq 전송모드)
    format_str = f'>h{len(filename)}sB{len(mode)}sB'           # 패킷 데이터를 생성, 해당 데이터를 소켓을 통해 서버 주소로 전송
    rrq_message = pack(format_str, OPCODE['RRQ'], bytes(filename, 'utf-8'), 0, bytes(mode, 'utf-8'), 0)   #Read Request 메시지를 생성하고 패킹
    sock.sendto(rrq_message, server_address)                   # 생성된 rrq 메시지를 서버 주소로 전송
    print(rrq_message)                                         # 생성된 rrq 메시지 출력

def send_ack(seq_num, server):                                     # ACK 메시지를 생성하는 함수
    format_str = f'>hh'                                            # 패킷 데이터의 형식을 지정하는 문자열
    ack_message = pack(format_str, OPCODE['ACK'], seq_num)     # 패킹된 ACK 메시지 생성
    sock.sendto(ack_message, server)                               # 패킷을 서버 주소로 전송
    print(f"블록 {seq_num}에 대한 확인을 전송했습니다.")                 # 전송한 ACK에 대한 print문 출력

# 명령행 인수를 파싱하기 위한 ArgumentParser 객체 생성
parser = argparse.ArgumentParser(description='TFTP 클라이언트 프로그램')              # 프로그램에 대한 설명
parser.add_argument(dest="host", help="서버 IP 주소", type=str)                     # 서버 IP 주소
parser.add_argument(dest="operation", help="파일을 가져오거나 전송합니다", type=str)    # 동작(파일 가져오기 또는 전송)
parser.add_argument(dest="filename", help="전송할 파일 이름", type=str)               # 전송할 파일 이름
parser.add_argument("-p", "--port", dest="port", type=int)            # 포트 번호 설정
args = parser.parse_args()                                                         # 명령행 인수를 해석, 결과를 args 객체에 저장

# UDP 소켓 생성
server_ip = args.host                                                      # 명령행 인수에서 받은 서버 IP 주소
server_port = args.port if args.port is not None else DEFAULT_PORT         # 명령행 인수에서 받은 포트 번호 또는 기본 포트 번호
server_address = (server_ip, server_port)                                  # 서버 주소 (IP 주소, 포트 번호)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)                    # IPv4와 UDP를 사용하는 소켓 생성
sock.settimeout(2)                                                         # 소켓 작업에 대한 타임아웃 설정

mode = DEFAULT_TRANSFER_MODE                                               # 전송 모드 초기화
operation = args.operation                                                 # 동작 초기화
filename = args.filename                                                   # 전송할 파일 이름 초기화

# 동작에 따라 RRQ 또는 WRQ 메시지 전송
if operation == 'get':                                                     # get 동작 일때
    send_rrq(filename, mode)                                               # rrq 함수 실행
elif operation == 'put':                                                   # put 동작 일때
    send_wrq(filename, mode)                                               # wrq 함수 실행
else:
    print("잘못된 동작입니다. 'get' 또는 'put'을 사용하세요.")                   # 유효하지 않는 동작을 하려고 했을때 print문 출력
    sock.close()                                                           # 소켓 닫기
    exit()                                                                 # 프로그램 종료

# 'get' 작업을 위해 서버로부터 데이터를 저장할 파일 열기
if operation == 'get':
    file = open(filename, 'wb')

expected_block_number = 1       # 예상하는 다음 블록의 번호, 초기값은 1
received_block_numbers = set()  # 중복된 블록 번호를 추적하기 위한 집합

while True:
    data, server_new_socket = sock.recvfrom(516)              # 데이터를 받고 서버의 소켓 주소도 함께 받음
    opcode = int.from_bytes(data[:2], 'big')         # 수신된 데이터의 첫 2바이트를 읽어 오퍼레이션 코드를 확인

    if opcode == OPCODE['DATA']:                                      # 데이터 패킷인 경우 처리
        block_number = int.from_bytes(data[2:4], 'big')      # 데이터 패킷의 블록 번호를 확인
        if block_number == expected_block_number and block_number not in received_block_numbers:
            send_ack(block_number, server_new_socket)            # 정상적인 블록이면 ACK를 보내서 확인
            received_block_numbers.add(block_number)             # 중복 확인을 위해 받은 블록 번호 집합에 추가
            file_block = data[4:]                                # 데이터 패킷에서 실제 파일 데이터를 추출
            file.write(file_block)                               # 파일에 데이터를 쓰기
            expected_block_number += 1                           # 예상 블록 번호를 증가하여 다음 블록을 기대
            print(f"서버로부터 블록 {block_number}을 받았습니다.")    # print문 출력
            print(file_block.decode())                           # 받은 데이터 출력
        else:
            send_ack(block_number, server_new_socket)            # 중복된 블록이거나 예상과 다른 블록이면 ACK 전송
            print(f"중복된 블록 {block_number}은 무시했습니다.")      # print문 출력
    elif opcode == OPCODE['ERROR']:                              # 오류 패킷인 경우 처리
        error_code = int.from_bytes(data[2:4], byteorder='big')  # 오류 코드 확인
        print(ERROR_CODE.get(error_code, "알 수 없는 오류"))       # 오류 코드에 따른 메세지 출력
        break   # 오류가 발생하면 루프 종료
    else:
        break   # DATA 또는 ERROR가 아닌 경우 루프 종료

    if len(data[4:]) < BLOCK_SIZE:                              # 마지막 데이터 패킷인지 확인
        if operation == 'get':                                  # 동작이 get 일때
            file.close()                                        # 'get' 작업 중이면 파일을 닫음
        break                                                   # 루프 종료

# 'put' 작업인 경우 모든 블록을 전송한 후 파일 닫기
if operation == 'put':                                          # 동작이 put 일때
    file = open(filename, 'rb')                                 # 'put' 작업 중이면 파일을 바이너리 모드로 열기
    block_number = 1                                            # 초기 블록 번호 설정
    max_retries = 3                                             # 최대 재전송 횟수
    sock.settimeout(5)                                          # 타임아웃을 5초로 설정

    while True:
        file_block = file.read(BLOCK_SIZE)                      # 파일에서 블록 크기만큼 데이터 읽기
        if not file_block:
            break                                               # 파일을 모두 읽었으면 루프 종료

        # 데이터 패킷 생성 및 전송
        data_packet = pack(f'>hh{len(file_block)}s', OPCODE['DATA'], block_number, file_block)
        sock.sendto(data_packet, server_new_socket)             # server_new_socket을 사용하여 데이터 전송

        retries = 0                                             # 재전송 횟수 초기화
        while retries < max_retries:                            # 최대 재전송 횟수에 도달하기 전까지 반복
            try:
                ack_data, _ = sock.recvfrom(516)                                 # ACK 수신 대기
                ack_opcode = int.from_bytes(ack_data[:2], 'big')        # ACK 패킷의 opcode를 읽어 정수로 변환
                ack_block_number = int.from_bytes(ack_data[2:4], 'big') # ACK 패킷의 블록 번호를 읽어 정수로 변환

                if ack_opcode == OPCODE['ACK'] and ack_block_number == block_number:   # 수신한 ACK 패킷의 opcode가 ACK이고 블록 번호가 현재 전송 중인 블록 번호와 일치하는지 확인
                    print(f"클라이언트로 ACK를 수신했습니다. \n블록 {ack_block_number}을 확인했습니다.")  # 일치하면 print문 출력
                    block_number += 1          # 블록 번호 증가
                    break                      # 확인을 성공적으로 받았으므로 루프 종료

            except socket.timeout:             #소켓 타임아웃 예외 처리
                print(f"ACK를 기다리는 동안 타임아웃 발생. 재시도 중... ({retries + 1}/{max_retries})")    # 소켓 타임아웃 예외 처리
                retries += 1                   # 재시도 횟수 증가

        if retries == max_retries:
            print(f"최대 재시도 횟수 도달. 종료합니다.")     # 최대 재전송 횟수에 도달하면 루프 종료
            break

    file.close()            # 파일을 모두 전송했거나 최대 재시도 횟수에 도달했을 때 파일 닫기
    sock.settimeout(2)      # 다시 기본 타임아웃으로 복원

sock.close()                # 소켓 닫기