import random
import time
import select
from network import create_sockets, parse_tcp_response, parse_icmp_response
from packets_creator import create_tcp_syn, create_tcp_rst


def start_scan(config):
    target_ip = config['target_ip']
    tcp_ports = set(config['tcp_ports'])
    udp_ports = config['udp_ports']
    timeout = config['timeout']

    open_ports = []
    tcp_responses = {}
    closed_udp_ports = set()

    tcp_socket, udp_socket, icmp_socket = create_sockets()

    source_port = random.randint(49152, 65535)

    for port in tcp_ports:
        packet = create_tcp_syn(target_ip, source_port, port)
        tcp_socket.sendto(packet, (target_ip, port))

    for port in udp_ports:
        udp_socket.sendto(b'', (target_ip, port))

    start_time = time.time()

    while time.time() - start_time < timeout:
        time_left = timeout - (time.time() - start_time)

        if time_left <= 0:
            break

        ready_sockets, _, _ = select.select([tcp_socket, icmp_socket], [], [], time_left)

        for socket in ready_sockets:
            if socket == tcp_socket:
                data, addr = tcp_socket.recvfrom(4096)
                if addr[0] == target_ip:
                    tcp_resp = parse_tcp_response(data)
                    if tcp_resp:
                        src_port, flags = tcp_resp
                        if src_port in tcp_ports and src_port not in tcp_responses:
                            tcp_responses[src_port] = flags
                            if flags == 0x12:
                                rst_packet = create_tcp_rst(target_ip, source_port, src_port)
                                tcp_socket.sendto(rst_packet, (target_ip, src_port))
            else:
                data, addr = icmp_socket.recvfrom(4096)
                if addr[0] == target_ip:
                    res = parse_icmp_response(data)
                    if res:
                        closed_udp_ports.add(res)

    tcp_socket.close()
    udp_socket.close()
    icmp_socket.close()

    for port in sorted(tcp_ports):
        if tcp_responses.get(port) == 0x12:
            open_ports.append({'protocol': 'TCP', 'port': port})

    for port in sorted(udp_ports):
        if port not in closed_udp_ports:
            open_ports.append({'protocol': 'UDP', 'port': port})

    return open_ports