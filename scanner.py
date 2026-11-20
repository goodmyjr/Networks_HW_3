import random
import time
import select
from network import create_sockets, parse_tcp_response, parse_icmp_response, guess_protocol
from packets_creator import create_tcp_syn, create_tcp_rst


def start_scan(config):
    target_ip = config['target_ip']
    tcp_ports = set(config['tcp_ports'])
    udp_ports = set(config['udp_ports'])
    timeout = config['timeout']
    guess = config['guess']
    verbose = config['verbose']

    open_ports = []
    tcp_responses = {}
    closed_udp_ports = set()
    tcp_send_times = {}
    tcp_ms = {}

    tcp_socket, udp_socket, icmp_socket = create_sockets()
    source_port = random.randint(49152, 65535)

    all_ports = [('TCP', port) for port in tcp_ports] + [('UDP', port) for port in udp_ports]

    index = 0
    end_time = None

    while True:
        sent_count = 0
        while index < len(all_ports) and sent_count < 64:
            protocol, port = all_ports[index]
            try:
                if protocol == 'TCP':
                    packet = create_tcp_syn(target_ip, source_port, port)
                    send_time = time.perf_counter()
                    tcp_socket.sendto(packet, (target_ip, port))
                    tcp_send_times[port] = send_time
                else:
                    udp_socket.sendto(b'', (target_ip, port))
                index += 1
                sent_count += 1
            except BlockingIOError:
                break

        if index == len(all_ports):
            if end_time is None:
                end_time = time.time() + timeout
            if not udp_ports and len(tcp_responses) == len(tcp_ports):
                break
            wait_time = end_time - time.time()
            if wait_time <= 0:
                break
        else:
            wait_time = 0.015

        ready_sockets, _, _ = select.select([tcp_socket, icmp_socket], [], [], wait_time)

        for socket in ready_sockets:
            if socket == tcp_socket:
                while True:
                    try:
                        data, addr = tcp_socket.recvfrom(4096)
                        recv_time = time.perf_counter()
                    except BlockingIOError:
                        break

                    if addr[0] == target_ip:
                        tcp_resp = parse_tcp_response(data)
                        if tcp_resp:
                            src_port, flags = tcp_resp
                            if src_port in tcp_ports and src_port not in tcp_responses:
                                tcp_responses[src_port] = flags
                                if flags == 0x12:
                                    send_time = tcp_send_times.get(src_port, recv_time)
                                    tcp_ms[src_port] = round((recv_time - send_time) * 1000, 2)
                                    rst_packet = create_tcp_rst(target_ip, source_port, src_port)
                                    try:
                                        tcp_socket.sendto(rst_packet, (target_ip, src_port))
                                    except BlockingIOError:
                                        pass
            else:
                while True:
                    try:
                        data, addr = icmp_socket.recvfrom(4096)
                    except BlockingIOError:
                        break

                    if addr[0] == target_ip:
                        res = parse_icmp_response(data)
                        if res:
                            closed_udp_ports.add(res)

    own_udp_port = udp_socket.getsockname()[1] if udp_ports else None

    tcp_socket.close()
    udp_socket.close()
    icmp_socket.close()

    for port in sorted(tcp_ports):
        if tcp_responses.get(port) == 0x12:
            entry = {'protocol': 'TCP', 'port': port}
            if guess:
                entry['app_level_protocol'] = guess_protocol(target_ip, 'TCP', port, timeout)
            if verbose:
                entry['time_ms'] = tcp_ms.get(port, 0)
            open_ports.append(entry)

    for port in sorted(udp_ports):
        if target_ip.startswith('127.') and port == own_udp_port:
            continue
        if port not in closed_udp_ports:
            entry = {'protocol': 'UDP', 'port': port}
            if guess:
                entry['app_level_protocol'] = guess_protocol(target_ip, 'UDP', port, timeout)
            if verbose:
                entry['time_ms'] = '-'
            open_ports.append(entry)

    return open_ports