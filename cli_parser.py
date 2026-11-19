import socket


def parse_args(args):
    if len(args) < 1:
        raise ValueError("Использование: portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...")

    config = {
        'timeout': 2.0,
        'num_threads': 1,
        'verbose': False,
        'guess': False,
        'target_ip': None,
        'tcp_ports': [],
        'udp_ports': []
    }

    index = 0

    while index < len(args):
        arg = args[index]

        if arg == '--timeout':
            if index + 1 >= len(args):
                raise ValueError("Опция --timeout требует время")

            timeout = float(args[index + 1])

            if timeout <= 0:
                raise ValueError("Таймаут должен быть больше 0")

            config['timeout'] = timeout
            index += 2

        elif arg in ('-j', '--num-threads'):
            if index + 1 >= len(args):
                raise ValueError(f"Опция {arg} требует значения")

            num_threads = int(args[index + 1])

            if num_threads < 1:
                raise ValueError("Число потоков не может быть менее 1")

            config['num_threads'] = num_threads
            index += 2

        elif arg in ('-v', '--verbose'):
            config['verbose'] = True
            index += 1

        elif arg in ('-g', '--guess'):
            config['guess'] = True
            index += 1

        elif arg.startswith('-'):
            raise ValueError(f"Неизвестная опция: {arg}")

        elif config['target_ip'] is None:
            try:
                config['target_ip'] = socket.gethostbyname(arg)
            except socket.gaierror:
                raise ValueError(f"Некорректный IP-адрес или хост: {arg}")

            index += 1

        else:
            if '/' in arg:
                protocol, ports_str = arg.split('/', 1)

                if not ports_str:
                    raise ValueError(f"Нет портов после '/': {arg}")

                ports = _parse_ports(ports_str)
            else:
                protocol = arg
                ports = list(range(1, 65536))

            protocol_lower = protocol.lower()

            if protocol_lower == 'tcp':
                config['tcp_ports'].extend(ports)
            elif protocol_lower == 'udp':
                config['udp_ports'].extend(ports)
            else:
                raise ValueError(f"Неподдерживаемый протокол: {protocol}")

            index += 1

    if config['target_ip'] is None:
        raise ValueError("Требуется IP-адрес или хост")

    if not config['tcp_ports'] and not config['udp_ports']:
        config['tcp_ports'] = list(range(1, 65536))
        config['udp_ports'] = list(range(1, 65536))

    return config


def _parse_ports(ports_str):
    ports = set()
    parts = ports_str.split(',')

    for part in parts:
        if not part:
            raise ValueError("Неверный ввод диапазона")

        if '-' in part:
            start_port_str, end_port_str = part.split('-')
            start_port = int(start_port_str)
            end_port = int(end_port_str)

            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError(f"Неверный диапазон портов: {part}")

            for port in range(start_port, end_port + 1):
                ports.add(port)
        else:
            port = int(part)

            if port < 1 or port > 65535:
                raise ValueError(f"Неверный номер порта: {port}")

            ports.add(port)

    return list(ports)