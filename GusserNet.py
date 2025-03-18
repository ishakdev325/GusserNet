import socket
import struct
import threading
from queue import Queue
import time
import sys
import argparse
import os
import json
import logging
import random
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional
import ssl
import hashlib
import colorama
from colorama import init, Fore, Back, Style

init(autoreset=True)
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY_HERE"

class GusserNet:
    def __init__(self):
        self.open_ports: List[int] = []
        self.timeout: float = 1.0
        self.thread_count: int = 200
        self.verbose: bool = False
        self.os_info: Dict[str, str] = {}
        self.service_info: Dict[int, str] = {}
        self.banner_info: Dict[int, str] = {}
        self.error_log: List[str] = []
        self.scan_start_time: float = 0.0
        self.logger = self.setup_logger()
        self.ascii_art = """
  ______                                                          __    __              __     
 /      \\                                                        /  \\  /  |            /  |    
/$$$$$$  | __    __   _______  _______   ______    ______        $$  \\ $$ |  ______   _$$ |_   
$$ | _$$/ /  |  /  | /       |/       | /      \\  /      \\       $$$  \\$$ | /      \\ / $$   |  
$$ |/    |$$ |  $$ |/$$$$$$$//$$$$$$$/ /$$$$$$  |/$$$$$$  |      $$$$  $$ |/$$$$$$  |$$$$$$/   
$$ |$$$$ |$$ |  $$ |$$      \\$$      \\ $$    $$ |$$ |  $$/       $$ $$ $$ |$$    $$ |  $$ | __ 
$$ \\__$$ |$$ \\__$$ | $$$$$$  |$$$$$$  |$$$$$$$$/ $$ |            $$ |$$$$ |$$$$$$$$/   $$ |/  |
$$    $$/ $$    $$/ /     $$//     $$/ $$       |$$ |            $$ | $$$ |$$       |  $$  $$/ 
 $$$$$$/   $$$$$$/  $$$$$$$/ $$$$$$$/   $$$$$$$/ $$/             $$/   $$/  $$$$$$$/    $$$$/  
        """

    def setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("GusserNet")
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(f"{Fore.CYAN}%(asctime)s - {Fore.RED}%(levelname)s - {Style.RESET_ALL}%(message)s"))
        logger.addHandler(handler)
        return logger

    def craft_tcp_packet(self, src_port: int, dst_port: int, seq: int = 0, flags: int = 0x02) -> bytes:
        try:
            tcp_header = struct.pack("!HHLLBBHHH",
                                     src_port, dst_port, seq, 0, 5 << 4, flags, 65535, 0, 0)
            checksum = self.calculate_checksum(tcp_header)
            return struct.pack("!HHLLBBHHH",
                               src_port, dst_port, seq, 0, 5 << 4, flags, 65535, checksum, 0)
        except struct.error as e:
            self.error_log.append(f"TCP Packet Crafting Error: {str(e)}")
            self.logger.error(f"TCP Packet Crafting Error: {str(e)}")
            return b""

    def calculate_checksum(self, data: bytes) -> int:
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum += (data[i] << 8) + data[i + 1]
            else:
                checksum += data[i] << 8
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = ~checksum & 0xffff
        return checksum

    def raw_scan_port(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(self.timeout)
            src_port = random.randint(1024, 65535)
            tcp_packet = self.craft_tcp_packet(src_port, port)
            sock.sendto(tcp_packet, (ip, port))
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, _ = sock.recvfrom(1024)
                    tcp_header = struct.unpack("!HHLLBBHHH", data[20:40])
                    if tcp_header[1] == port and (tcp_header[5] & 0x12) == 0x12:
                        self.open_ports.append(port)
                        return True
                except socket.timeout:
                    continue
            sock.close()
        except PermissionError:
            self.error_log.append("Raw scan requires root privileges")
            self.logger.error(f"{Fore.RED}Raw scan requires root privileges{Style.RESET_ALL}")
            return False
        except Exception as e:
            self.error_log.append(f"Raw Scan Error on port {port}: {str(e)}")
            self.logger.error(f"{Fore.RED}Raw Scan Error on port {port}: {str(e)}{Style.RESET_ALL}")
            return False
        return False

    def tcp_scan_port(self, ip: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                self.open_ports.append(port)
            sock.close()
        except Exception as e:
            self.error_log.append(f"TCP Scan Error on port {port}: {str(e)}")
            self.logger.error(f"{Fore.RED}TCP Scan Error on port {port}: {str(e)}{Style.RESET_ALL}")

    def udp_scan_port(self, ip: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            payload = b"GusserNet UDP Probe"
            sock.sendto(payload, (ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                if data:
                    self.open_ports.append(port)
                    self.service_info[port] = f"UDP Response: {data.decode(errors='ignore')}"
            except socket.timeout:
                pass
            sock.close()
        except Exception as e:
            self.error_log.append(f"UDP Scan Error on port {port}: {str(e)}")
            self.logger.error(f"{Fore.RED}UDP Scan Error on port {port}: {str(e)}{Style.RESET_ALL}")

    def os_detection(self, ip: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(self.timeout)
            sock.sendto(self.craft_tcp_packet(random.randint(1024, 65535), port), (ip, port))
            data, _ = sock.recvfrom(1024)
            ttl = struct.unpack("B", data[8:9])[0]
            tcp_header = struct.unpack("!HHLLBBHHH", data[20:40])
            window_size = tcp_header[6]
            if ttl <= 64:
                self.os_info["OS"] = "Linux/Unix"
            elif ttl <= 128:
                self.os_info["OS"] = "Windows"
            else:
                self.os_info["OS"] = "Unknown"
            self.os_info["TTL"] = str(ttl)
            self.os_info["Window Size"] = str(window_size)
            if len(data) > 40:
                options = data[40:]
                if b"\x02\x04" in options:
                    self.os_info["MSS"] = str(struct.unpack("!H", options[2:4])[0])
            sock.close()
        except Exception as e:
            self.error_log.append(f"OS Detection Error: {str(e)}")
            self.logger.error(f"{Fore.RED}OS Detection Error: {str(e)}{Style.RESET_ALL}")
            self.os_info["OS"] = "Detection failed"

    def grab_banner(self, ip: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            if port == 443:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=ip)
            sock.connect((ip, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode(errors='ignore')
            self.banner_info[port] = banner.strip()
            sock.close()
        except Exception as e:
            self.error_log.append(f"Banner Grab Error on port {port}: {str(e)}")
            self.logger.error(f"{Fore.RED}Banner Grab Error on port {port}: {str(e)}{Style.RESET_ALL}")
            self.banner_info[port] = "No banner"

    def shodan_lookup(self, ip: str) -> Dict[str, str]:
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    "OS": data.get("os", "Unknown"),
                    "ISP": data.get("isp", "Unknown"),
                    "Last Update": data.get("last_update", "Unknown"),
                    "Vulns": ", ".join(data.get("vulns", [])) or "None"
                }
            else:
                self.error_log.append(f"Shodan Error: {response.status_code}")
                self.logger.error(f"{Fore.RED}Shodan Error: {response.status_code}{Style.RESET_ALL}")
                return {}
        except Exception as e:
            self.error_log.append(f"Shodan Lookup Error: {str(e)}")
            self.logger.error(f"{Fore.RED}Shodan Lookup Error: {str(e)}{Style.RESET_ALL}")
            return {}

    def scan_range(self, ip: str, start_port: int, end_port: int, raw: bool = False, udp: bool = False) -> List[int]:
        port_queue = Queue()
        for port in range(start_port, end_port + 1):
            port_queue.put(port)

        def worker():
            while not port_queue.empty():
                port = port_queue.get()
                if udp:
                    self.udp_scan_port(ip, port)
                elif raw:
                    self.raw_scan_port(ip, port)
                else:
                    self.tcp_scan_port(ip, port)
                port_queue.task_done()

        threads = []
        for _ in range(min(self.thread_count, end_port - start_port + 1)):
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
        return sorted(self.open_ports)

    def fingerprint_service(self, ip: str, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            if port in [80, 443]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                response = sock.recv(1024).decode(errors='ignore')
                if "Server:" in response:
                    server = response.split("Server:")[1].split("\r\n")[0].strip()
                    self.service_info[port] = f"HTTP - {server}"
            elif port == 22:
                sock.send(b"SSH-2.0-GusserNet\r\n")
                response = sock.recv(1024).decode(errors='ignore')
                self.service_info[port] = f"SSH - {response.strip()}"
            sock.close()
        except Exception as e:
            self.error_log.append(f"Fingerprint Error on port {port}: {str(e)}")
            self.logger.error(f"{Fore.RED}Fingerprint Error on port {port}: {str(e)}{Style.RESET_ALL}")

    def resolve_host(self, target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            self.error_log.append(f"Host Resolution Error: {str(e)}")
            self.logger.error(f"{Fore.RED}Host Resolution Error: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.RED}Error: Could not resolve {target}{Style.RESET_ALL}")
            sys.exit(1)

    def get_service(self, port: int) -> str:
        try:
            return socket.getservbyport(port)
        except:
            return "unknown"

def main():
    parser = argparse.ArgumentParser(description=f"{Fore.GREEN}Gusser Net - Next-Gen Network Scanner{Style.RESET_ALL}")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g., 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Number of threads")
    parser.add_argument("-o", "--output", help="Output results to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("--top-ports", type=int, help="Scan top N common ports")
    parser.add_argument("--raw", action="store_true", help="Use raw socket scanning (root required)")
    parser.add_argument("--udp", action="store_true", help="Perform UDP scanning")
    parser.add_argument("--os-detect", action="store_true", help="Perform advanced OS detection")
    parser.add_argument("--stealth", action="store_true", help="Stealth SYN scan mode")
    parser.add_argument("--banner", action="store_true", help="Grab service banners")
    parser.add_argument("--shodan", action="store_true", help="Integrate Shodan lookup")
    parser.add_argument("--fingerprint", action="store_true", help="Fingerprint services")

    args = parser.parse_args()

    scanner = GusserNet()
    scanner.thread_count = args.threads
    scanner.timeout = args.timeout
    scanner.verbose = args.verbose
    scanner.scan_start_time = time.time()

    print(f"{Fore.CYAN}{scanner.ascii_art}{Style.RESET_ALL}")
    target_ip = scanner.resolve_host(args.target)
    print(f"{Fore.GREEN}Starting Gusser Net scan on {args.target} ({target_ip}){Style.RESET_ALL}")

    if args.top_ports:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080][:args.top_ports]
        ports_to_scan = common_ports
    else:
        try:
            start_port, end_port = map(int, args.ports.split('-'))
            ports_to_scan = range(start_port, end_port + 1)
        except ValueError as e:
            scanner.error_log.append(f"Port Range Error: {str(e)}")
            scanner.logger.error(f"{Fore.RED}Port Range Error: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.RED}Error: Invalid port range{Style.RESET_ALL}")
            sys.exit(1)

    scanner.open_ports = scanner.scan_range(target_ip, min(ports_to_scan), max(ports_to_scan), raw=args.raw or args.stealth, udp=args.udp)

    if args.os_detect and scanner.open_ports:
        scanner.os_detection(target_ip, scanner.open_ports[0])

    if args.banner:
        for port in scanner.open_ports:
            scanner.grab_banner(target_ip, port)

    if args.fingerprint:
        for port in scanner.open_ports:
            scanner.fingerprint_service(target_ip, port)

    shodan_data = scanner.shodan_lookup(target_ip) if args.shodan else {}

    scan_end_time = time.time()
    print(f"{Fore.GREEN}Scan completed in {scan_end_time - scanner.scan_start_time:.2f} seconds{Style.RESET_ALL}")

    if scanner.open_ports:
        print(f"{Fore.YELLOW}Open ports on {target_ip}:{Style.RESET_ALL}")
        for port in scanner.open_ports:
            service = scanner.service_info.get(port, scanner.get_service(port))
            print(f"{Fore.CYAN}Port {port}/{'udp' if args.udp else 'tcp'} - Service: {service}{Style.RESET_ALL}")
            if port in scanner.banner_info:
                print(f"{Fore.MAGENTA}  Banner: {scanner.banner_info[port]}{Style.RESET_ALL}")
            if args.verbose:
                print(f"{Fore.BLUE}  - Verbose: Port {port} is open{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No open ports found.{Style.RESET_ALL}")

    if args.os_detect and scanner.os_info:
        print(f"{Fore.GREEN}OS Detection: {scanner.os_info}{Style.RESET_ALL}")

    if shodan_data:
        print(f"{Fore.YELLOW}Shodan Info: {shodan_data}{Style.RESET_ALL}")

    if scanner.error_log:
        print(f"\n{Fore.RED}Errors Encountered:{Style.RESET_ALL}")
        for error in scanner.error_log:
            print(f"{Fore.RED}  - {error}{Style.RESET_ALL}")

    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(f"Gusser Net Scan Results for {target_ip}\n")
                f.write(f"Scan completed in {scan_end_time - scanner.scan_start_time:.2f} seconds\n")
                for port in scanner.open_ports:
                    service = scanner.service_info.get(port, scanner.get_service(port))
                    f.write(f"Port {port}/{'udp' if args.udp else 'tcp'} - Service: {service}\n")
                    if port in scanner.banner_info:
                        f.write(f"  Banner: {scanner.banner_info[port]}\n")
                if args.os_detect:
                    f.write(f"OS Detection: {scanner.os_info}\n")
                if shodan_data:
                    f.write(f"Shodan Info: {shodan_data}\n")
                if scanner.error_log:
                    f.write("\nErrors:\n" + "\n".join(f"  - {e}" for e in scanner.error_log))
            print(f"{Fore.GREEN}Results saved to {args.output}{Style.RESET_ALL}")
        except IOError as e:
            scanner.error_log.append(f"File Write Error: {str(e)}")
            scanner.logger.error(f"{Fore.RED}File Write Error: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.RED}Error saving to file: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)