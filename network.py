import socket
import struct

def create_sockets():
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

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


def _parse_ip_header(packet):
    if len(packet) < 20:
        return None

    ip_header = packet[0:20]

    return struct.unpack('!BBHHHBBH4s4s', ip_header)
