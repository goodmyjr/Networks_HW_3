import socket
import struct
from packets_creator import create_dns_query


def create_sockets():
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    icmp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)

    tcp_socket.setblocking(False)
    udp_socket.setblocking(False)
    icmp_socket.setblocking(False)

    return tcp_socket, udp_socket, icmp_socket


def parse_tcp_response(packet):
    ip_header_fields = _parse_ip_header(packet)
    version_and_ihl = ip_header_fields[0]
    ihl = version_and_ihl & 0xF
    ip_header_end = ihl * 4
    tcp_header = packet[ip_header_end:ip_header_end + 20]

    if len(tcp_header) < 20:
        return None

    tcp_header_fields = struct.unpack('!HHLLBBHHH', tcp_header)
    src_port = tcp_header_fields[0]
    flags = tcp_header_fields[5]

    return src_port, flags


def parse_icmp_response(packet):
    ip_header_fields = _parse_ip_header(packet)
    version_and_ihl = ip_header_fields[0]
    ihl = version_and_ihl & 0xF
    ip_header_end = ihl * 4
    inner_ip_start = ip_header_end + 8
    icmp_header = packet[ip_header_end:inner_ip_start]

    if len(icmp_header) < 8:
        return None

    type_and_code = struct.unpack('!BB', icmp_header[:2])
    icmp_type = type_and_code[0]
    icmp_code = type_and_code[1]

    if icmp_type == 3 and icmp_code == 3:
        inner_ip_header = packet[inner_ip_start:inner_ip_start + 20]

        if len(inner_ip_header) < 20:
            return None

        inner_ip_header_fields = _parse_ip_header(inner_ip_header)
        inner_ip_header_end = (inner_ip_header_fields[0] & 0xF) * 4
        inner_udp_start = inner_ip_start + inner_ip_header_end
        inner_udp_header = packet[inner_udp_start:inner_udp_start + 8]

        if len(inner_udp_header) < 8:
            return None

        udp_header_fields = struct.unpack('!HHHH', inner_udp_header)
        dest_port = udp_header_fields[1]

        return dest_port

    return None


def guess_protocol(target_ip, protocol, port, timeout):
    probe_timeout = min(timeout, 2.0)

    if protocol == 'TCP':
        if _probe_tcp_http(target_ip, port, probe_timeout):
            return 'HTTP'
        if _probe_tcp_echo(target_ip, port, probe_timeout):
            return 'ECHO'
        if _probe_tcp_dns(target_ip, port, probe_timeout):
            return 'DNS'
        return '-'

    if _probe_udp_dns(target_ip, port, probe_timeout):
        return 'DNS'
    if _probe_udp_echo(target_ip, port, probe_timeout):
        return 'ECHO'
    return '-'


def _probe_tcp_http(target_ip, port, timeout):
    request = b'GET / HTTP/1.1\r\nHost: ' + target_ip.encode('ascii') + b'\r\nConnection: close\r\n\r\n'

    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            sock.sendall(request)
            response = sock.recv(1024)

            return response.startswith(b'HTTP/')
    except OSError:
        return False


def _probe_tcp_echo(target_ip, port, timeout):
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            sock.sendall(b'ECHO_CHECK\r\n')
            response = sock.recv(1024)

            return response == b'ECHO_CHECK\r\n'
    except OSError:
        return False


def _probe_tcp_dns(target_ip, port, timeout):
    dns_query = create_dns_query()
    payload = struct.pack('!H', len(dns_query)) + dns_query

    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            sock.sendall(payload)
            response = sock.recv(1024)

            return len(response) >= 14 and response[2:4] == dns_query[:2] and (response[4] & 0x80) != 0
    except OSError:
        return False


def _probe_udp_echo(target_ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b'ECHO_CHECK', (target_ip, port))
            response, _ = sock.recvfrom(1024)

            return response == b'ECHO_CHECK'
    except OSError:
        return False


def _probe_udp_dns(target_ip, port, timeout):
    dns_query = create_dns_query()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(dns_query, (target_ip, port))
            response, _ = sock.recvfrom(1024)

            return len(response) >= 12 and response[:2] == dns_query[:2] and (response[2] & 0x80) != 0
    except OSError:
        return False


def _parse_ip_header(packet):
    if len(packet) < 20:
        return None

    ip_header = packet[0:20]

    return struct.unpack('!BBHHHBBH4s4s', ip_header)