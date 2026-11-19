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
        print(f"{port_info['protocol']} {port_info['port']}")


if __name__ == "__main__":
    main()