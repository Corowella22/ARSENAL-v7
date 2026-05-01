import socket
import subprocess
import platform
import re
import time
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf as scapy_conf
    SCAPY = True
except Exception:
    SCAPY = False

try:
    import netifaces
    NETIFACES = True
except Exception:
    NETIFACES = False

SERVICES: Dict[int, str] = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9100: 'Printer',
    631: 'IPP', 161: 'SNMP', 1900: 'UPnP', 5353: 'mDNS',
    5985: 'WinRM', 8291: 'WinBox',
}

MAC_VENDORS: Dict[str, str] = {
    '00:50:56': 'VMware', '00:0C:29': 'VMware',
    '08:00:27': 'VirtualBox', '00:1A:2B': 'Cisco',
    '00:25:00': 'Cisco', 'B8:27:EB': 'Raspberry Pi',
    'DC:A6:32': 'Raspberry Pi', '3C:22:FB': 'Apple',
    'F0:18:98': 'Apple', '30:B5:C2': 'TP-Link',
    '50:C7:BF': 'TP-Link', 'EC:08:6B': 'TP-Link',
    '00:1D:7E': 'D-Link', '1C:7E:E5': 'D-Link',
    'C8:3A:35': 'Tenda', '20:47:DA': 'Dell',
    '3C:D9:2B': 'HP', '48:21:0B': 'Samsung',
    '7C:61:66': 'Huawei', '48:8A:D2': 'Xiaomi',
    '00:0D:3A': 'Microsoft', 'B4:2E:99': 'Lenovo',
    '54:27:1E': 'Google', 'A4:77:33': 'Google',
}


@dataclass
class Device:
    ip: str
    mac: str = 'Unknown'
    hostname: str = 'Unknown'
    vendor: str = 'Unknown'
    device_type: str = 'unknown'
    os_guess: str = 'Unknown'
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    status: str = 'online'
    latency: float = 0.0
    last_seen: float = 0.0
    is_gateway: bool = False
    ttl: int = 0
    x: int = 0
    y: int = 0

    def to_dict(self) -> dict:
        return {
            'ip': self.ip, 'mac': self.mac,
            'hostname': self.hostname, 'vendor': self.vendor,
            'device_type': self.device_type, 'os_guess': self.os_guess,
            'open_ports': self.open_ports, 'services': self.services,
            'status': self.status, 'latency': self.latency,
            'is_gateway': self.is_gateway, 'ttl': self.ttl,
        }


class NetworkScanner:
    def __init__(self):
        self.devices: Dict[str, Device] = {}
        self.gateway_ip: str = ''
        self.local_ip: str = ''
        self.subnet: str = ''
        self.interface: str = ''
        self.is_scanning: bool = False
        self._lock = threading.Lock()

    def get_network_info(self) -> dict:
        try:
            if NETIFACES:
                gws = netifaces.gateways()
                default = gws.get('default', {})
                if netifaces.AF_INET in default:
                    self.gateway_ip = default[netifaces.AF_INET][0]
                    self.interface  = default[netifaces.AF_INET][1]
                    addrs = netifaces.ifaddresses(self.interface)
                    if netifaces.AF_INET in addrs:
                        info = addrs[netifaces.AF_INET][0]
                        self.local_ip = info['addr']
                        mask = info.get('netmask', '255.255.255.0')
                        net  = ipaddress.IPv4Network(
                            f'{self.local_ip}/{mask}', strict=False)
                        self.subnet = str(net)
            if not self.local_ip:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                self.local_ip = s.getsockname()[0]
                s.close()
                p = self.local_ip.split('.')
                self.subnet     = f'{p[0]}.{p[1]}.{p[2]}.0/24'
                self.gateway_ip = f'{p[0]}.{p[1]}.{p[2]}.1'
        except Exception:
            self.local_ip   = '127.0.0.1'
            self.subnet     = '127.0.0.0/8'
            self.gateway_ip = '127.0.0.1'
        return {
            'local_ip': self.local_ip, 'gateway': self.gateway_ip,
            'subnet': self.subnet, 'interface': self.interface,
        }

    def lookup_vendor(self, mac: str) -> str:
        if not mac or mac == 'Unknown':
            return 'Unknown'
        return MAC_VENDORS.get(mac.upper()[:8], 'Unknown')

    def ping_host(self, ip: str):
        try:
            if SCAPY:
                pkt   = IP(dst=ip) / ICMP()
                reply = sr1(pkt, timeout=1, verbose=0)
                if reply:
                    return True, (reply.time - pkt.sent_time) * 1000, reply.ttl
            else:
                flag = '-n' if platform.system() == 'Windows' else '-c'
                res  = subprocess.run(
                    f'ping {flag} 1 -W 1 {ip}',
                    shell=True, capture_output=True,
                    text=True, timeout=3)
                if res.returncode == 0:
                    ttl_m  = re.search(r'[Tt][Tt][Ll]=(\d+)', res.stdout)
                    time_m = re.search(r'[Tt]ime[=<](\d+\.?\d*)', res.stdout)
                    return (True,
                            float(time_m.group(1)) if time_m else 0.0,
                            int(ttl_m.group(1))    if ttl_m  else 0)
        except Exception:
            pass
        return False, 0.0, 0

    def arp_scan(self) -> list:
        if SCAPY:
            try:
                scapy_conf.verb = 0
                answered, _ = srp(
                    Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.subnet),
                    timeout=3, verbose=0)
                return [{'ip': rx.psrc, 'mac': rx.hwsrc} for _, rx in answered]
            except Exception:
                pass
        return self._arp_fallback()

    def _arp_fallback(self) -> list:
        found = []
        try:
            hosts = list(ipaddress.IPv4Network(self.subnet, strict=False).hosts())[:254]
            with ThreadPoolExecutor(max_workers=50) as ex:
                futs = {ex.submit(self.ping_host, str(h)): str(h) for h in hosts}
                for f in as_completed(futs):
                    try:
                        f.result()
                    except Exception:
                        pass
            sep  = '-' if platform.system() == 'Windows' else ':'
            cmd  = 'arp -a' if platform.system() == 'Windows' else 'arp -an'
            out  = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
            mac_re = r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}'
            for line in out.split('\n'):
                ip_m  = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                mac_m = re.search(mac_re, line)
                if ip_m and mac_m:
                    ip = ip_m.group(1)
                    if not ip.endswith('.255'):
                        found.append({
                            'ip':  ip,
                            'mac': mac_m.group(0).replace('-', ':'),
                        })
        except Exception:
            pass
        return found

    def scan_ports(self, ip: str, ports: Optional[List[int]] = None) -> Dict[int, str]:
        if ports is None:
            ports = list(SERVICES.keys())
        result: Dict[int, str] = {}

        def _check(port: int):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return port, SERVICES.get(port, f'Port-{port}')
                s.close()
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            for fut in as_completed([ex.submit(_check, p) for p in ports]):
                r = fut.result()
                if r:
                    result[r[0]] = r[1]
        return result

    def _guess_type(self, dev: Device) -> str:
        if dev.is_gateway:
            return 'router'
        v = dev.vendor.lower()
        h = dev.hostname.lower()
        if any(x in v for x in ['cisco', 'tp-link', 'd-link', 'netgear',
                                  'mikrotik', 'ubiquiti', 'tenda', 'huawei']):
            return 'wireless_ap'
        if any(x in h for x in ['router', 'gateway', 'gw']):
            return 'router'
        if len(set(dev.open_ports) & {22, 80, 443, 3306, 5432}) >= 3:
            return 'server'
        if any(x in v for x in ['apple', 'samsung', 'xiaomi', 'huawei']):
            return 'phone'
        if 'raspberry' in v:
            return 'iot'
        if any(x in v for x in ['dell', 'hp', 'lenovo', 'microsoft']):
            return 'computer'
        if dev.open_ports:
            return 'computer'
        return 'unknown'

    def _guess_os(self, dev: Device) -> str:
        if dev.ttl > 0:
            if dev.ttl <= 64:  return 'Linux / Unix'
            if dev.ttl <= 128: return 'Windows'
            return 'Network Device'
        v = dev.vendor.lower()
        if 'apple'     in v: return 'macOS / iOS'
        if 'microsoft' in v: return 'Windows'
        if 'raspberry' in v: return 'Linux'
        return 'Unknown'

    def full_scan(self, port_scan: bool = True, progress_cb=None):
        self.is_scanning = True
        self.get_network_info()
        if progress_cb:
            progress_cb(5, 'Network info...')

        if progress_cb:
            progress_cb(10, 'ARP scanning...')
        arp_results = self.arp_scan()
        total = len(arp_results)

        for idx, entry in enumerate(arp_results):
            if not self.is_scanning:
                break
            ip  = entry['ip']
            mac = entry['mac']
            pct = 20 + int((idx / max(total, 1)) * 70)
            if progress_cb:
                progress_cb(pct, f'Analyzing {ip} ({idx+1}/{total})')

            dev = Device(ip=ip, mac=mac, last_seen=time.time())
            if ip == self.gateway_ip:
                dev.is_gateway = True

            try:
                dev.hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            dev.vendor = self.lookup_vendor(mac)
            alive, lat, ttl = self.ping_host(ip)
            dev.latency = lat
            dev.ttl     = ttl
            dev.status  = 'online' if alive else 'offline'

            if port_scan and alive:
                pr = self.scan_ports(ip)
                dev.open_ports = sorted(pr.keys())
                dev.services   = pr

            dev.os_guess    = self._guess_os(dev)
            dev.device_type = self._guess_type(dev)

            with self._lock:
                self.devices[ip] = dev

        if self.local_ip and self.local_ip not in self.devices:
            with self._lock:
                self.devices[self.local_ip] = Device(
                    ip=self.local_ip,
                    hostname=socket.gethostname(),
                    device_type='computer',
                    status='online',
                    os_guess=f'{platform.system()} {platform.release()}',
                )

        self.is_scanning = False
        if progress_cb:
            progress_cb(100, 'Complete!')
        return self.devices

    def stop_scan(self):
        self.is_scanning = False