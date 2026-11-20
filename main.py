import sys
from cli_parser import parse_args
from scanner import start_scan


def main():
    try:
        config = parse_args(sys.argv[1:])
        open_ports = start_scan(config)
    except ValueError as e:
        print(f"Ошибка параметров: {e}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("Для работы сырых сокетов требуются права суперпользователя", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"{e}", file=sys.stderr)
        sys.exit(1)

    for port_info in open_ports:
        parts = [port_info['protocol'], str(port_info['port'])]

        if 'time_ms' in port_info:
            parts.append(str(port_info['time_ms']))
        if 'app_level_protocol' in port_info:
            parts.append(port_info['app_level_protocol'])

        print(' '.join(parts))


if __name__ == "__main__":
    main()