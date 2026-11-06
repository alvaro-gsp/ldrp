from ldrp.app import run_server, DEFAULT_FOLDER
import argparse
import pathlib


def main():
    parser = argparse.ArgumentParser(description="ldrp")
    parser.add_argument("folder", nargs="?", default=None, help="Shared folder path")
    parser.add_argument("--ip", default=None, help="Override local IP (e.g. 192.168.1.11)")
    parser.add_argument("--port", type=int, default=8000, help="Listen port (default 8000)")
    args = parser.parse_args()

    target_dir = pathlib.Path(args.folder).resolve() if args.folder else DEFAULT_FOLDER
    run_server(folder=target_dir, port=args.port, override_ip=args.ip)


if __name__ == "__main__":
    main()
