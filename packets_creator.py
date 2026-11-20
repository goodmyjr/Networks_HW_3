import socket
import struct

_source_ip_cache = {}


def create_tcp_syn(target_ip, source_port, dest_port):
    seq = 0
    ack_seq = 0
    doff = 5
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = 5840
    temp_checksum = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    temp_tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, temp_checksum, urg_ptr)

    source_ip = _get_source_ip(target_ip)
    dest_ip = socket.inet_aton(socket.gethostbyname(target_ip))

    temp_header = struct.pack('!4s4sBBH', source_ip, dest_ip, 0, socket.IPPROTO_TCP, len(temp_tcp_header)) + temp_tcp_header

    checksum = _calculate_checksum(temp_header)

    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, checksum, urg_ptr)

    return tcp_header


def create_tcp_rst(target_ip, source_port, dest_port):
    seq = 1
    ack_seq = 0
    doff = 5
    fin = 0
    syn = 0
    rst = 1
    psh = 0
    ack = 0
    urg = 0
    window = 5840
    temp_checksum = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    temp_tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, temp_checksum, urg_ptr)

    source_ip = _get_source_ip(target_ip)
    dest_ip = socket.inet_aton(socket.gethostbyname(target_ip))

    temp_header = struct.pack('!4s4sBBH', source_ip, dest_ip, 0, socket.IPPROTO_TCP, len(temp_tcp_header)) + temp_tcp_header

    checksum = _calculate_checksum(temp_header)

    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, checksum, urg_ptr)

    return tcp_header


def create_dns_query():
    header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    question = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
    return header + question


def _get_source_ip(target_ip):
    if target_ip not in _source_ip_cache:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_socket:
            temp_socket.connect((target_ip, 80))
            local_ip = temp_socket.getsockname()[0]
        _source_ip_cache[target_ip] = socket.inet_aton(local_ip)
    return _source_ip_cache[target_ip]


def _calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'

    s = 0

    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)

    return ~s & 0xffff