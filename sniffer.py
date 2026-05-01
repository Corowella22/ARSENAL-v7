import threading
import time
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Callable, Optional
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Ether, Raw, DNSQR, wrpcap
    SCAPY = True
except Exception:
    SCAPY = False


@dataclass
class Packet:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_mac: str
    dst_mac: str
    protocol: str
    src_port: int
    dst_port: int
    length: int
    info: str
    flags: str = ''


class TrafficSniffer:
    def __init__(self):
        self.is_sniffing: bool = False
        self.packets: List[Packet] = []
        self.raw_packets: list = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._pkt_cb: Optional[Callable] = None
        self.stats: dict = self._empty_stats()
        self._pps_cnt: int = 0
        self._pps_time: float = time.time()

    def _empty_stats(self) -> dict:
        return {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'top_talkers': defaultdict(int),
            'packets_per_second': 0,
        }

    def _process(self, pkt):
        if not self.is_sniffing:
            return
        try:
            p = Packet(
                timestamp=datetime.now().strftime('%H:%M:%S.%f')[:-3],
                src_ip='', dst_ip='', src_mac='', dst_mac='',
                protocol='', src_port=0, dst_port=0,
                length=len(pkt), info='',
            )
            if pkt.haslayer(Ether):
                p.src_mac = pkt[Ether].src
                p.dst_mac = pkt[Ether].dst
            if pkt.haslayer(IP):
                p.src_ip = pkt[IP].src
                p.dst_ip = pkt[IP].dst
                if pkt.haslayer(TCP):
                    p.protocol  = 'TCP'
                    p.src_port  = pkt[TCP].sport
                    p.dst_port  = pkt[TCP].dport
                    p.flags     = str(pkt[TCP].flags)
                    if   p.dst_port in (80, 8080)  or p.src_port in (80, 8080):  p.protocol = 'HTTP'
                    elif p.dst_port in (443, 8443) or p.src_port in (443, 8443): p.protocol = 'TLS/SSL'
                    elif p.dst_port == 22          or p.src_port == 22:           p.protocol = 'SSH'
                    p.info = f'{p.src_port}→{p.dst_port} [{p.flags}]'
                elif pkt.haslayer(UDP):
                    p.protocol = 'UDP'
                    p.src_port = pkt[UDP].sport
                    p.dst_port = pkt[UDP].dport
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        p.protocol = 'DNS'
                        try:
                            p.info = f'Query: {pkt[DNSQR].qname.decode("utf-8", errors="ignore")}'
                        except Exception:
                            p.info = 'DNS Query'
                    if not p.info:
                        p.info = f'{p.src_port}→{p.dst_port}'
                elif pkt.haslayer(ICMP):
                    p.protocol = 'ICMP'
                    names = {0: 'Echo Reply', 8: 'Echo Request', 3: 'Unreachable'}
                    p.info = names.get(pkt[ICMP].type, f'Type={pkt[ICMP].type}')
            elif pkt.haslayer(ARP):
                p.protocol = 'ARP'
                p.src_ip   = pkt[ARP].psrc
                p.dst_ip   = pkt[ARP].pdst
                p.info     = 'Request' if pkt[ARP].op == 1 else 'Reply'

            with self._lock:
                self.packets.append(p)
                self.raw_packets.append(pkt)
                self.stats['total_packets'] += 1
                self.stats['total_bytes']   += p.length
                self.stats['protocols'][p.protocol] += 1
                if p.src_ip:
                    self.stats['top_talkers'][p.src_ip] += 1
                self._pps_cnt += 1
                now = time.time()
                if now - self._pps_time >= 1.0:
                    self.stats['packets_per_second'] = self._pps_cnt
                    self._pps_cnt  = 0
                    self._pps_time = now

            if self._pkt_cb:
                self._pkt_cb(p)
        except Exception:
            pass

    def start(self, iface=None, bpf: str = None, pkt_cb: Callable = None) -> bool:
        if not SCAPY:
            return False
        self.is_sniffing = True
        self._pkt_cb     = pkt_cb

        def _run():
            try:
                sniff(iface=iface, filter=bpf, prn=self._process,
                      stop_filter=lambda x: not self.is_sniffing,
                      store=False)
            except Exception:
                pass
            self.is_sniffing = False

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self.is_sniffing = False
        if self._thread:
            self._thread.join(timeout=2)

    def clear(self):
        with self._lock:
            self.packets.clear()
            self.raw_packets.clear()
            self.stats = self._empty_stats()

    def save_pcap(self, filename: str) -> bool:
        if SCAPY and self.raw_packets:
            try:
                wrpcap(filename, self.raw_packets)
                return True
            except Exception:
                pass
        return False