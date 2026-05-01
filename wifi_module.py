import subprocess
import platform
import re
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable

AP_VENDORS: Dict[str, str] = {
    '00:1A:2B': 'Cisco',   '00:25:00': 'Cisco',
    '30:B5:C2': 'TP-Link', '50:C7:BF': 'TP-Link', 'EC:08:6B': 'TP-Link',
    '00:1D:7E': 'D-Link',  '1C:7E:E5': 'D-Link',
    '20:CF:30': 'ASUS',    'F8:32:E4': 'ASUS',
    '00:14:BF': 'Linksys', '00:18:F8': 'Netgear',
    '20:0C:C8': 'Netgear', 'E4:F4:C6': 'Netgear',
    '7C:61:66': 'Huawei',  '00:E0:FC': 'Huawei',
    'C8:3A:35': 'Tenda',   '88:C6:26': 'Google',
}


@dataclass
class WiFiNet:
    ssid: str
    bssid: str
    signal: int = 0
    signal_dbm: int = -100
    channel: int = 0
    frequency: int = 0
    security: str = 'Unknown'
    encryption: str = ''
    band: str = ''
    vendor: str = 'Unknown'
    hidden: bool = False
    is_connected: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    x: int = 0
    y: int = 0

    def quality(self) -> str:
        d = self.signal_dbm
        if d >= -50: return 'Excellent'
        if d >= -60: return 'Good'
        if d >= -70: return 'Fair'
        if d >= -80: return 'Weak'
        return 'Very Weak'

    def bars(self) -> str:
        d = self.signal_dbm
        if d >= -50: return '█████'
        if d >= -60: return '████░'
        if d >= -70: return '███░░'
        if d >= -80: return '██░░░'
        if d >= -90: return '█░░░░'
        return '░░░░░'


class WiFiScanner:
    def __init__(self):
        self.networks: Dict[str, WiFiNet] = {}
        self.is_scanning: bool = False
        self.current_ssid: str = ''
        self.current_bssid: str = ''
        self._lock = threading.Lock()

    def _vendor(self, mac: str) -> str:
        return AP_VENDORS.get(mac[:8].upper(), 'Unknown')

    def _add(self, net: WiFiNet, cb=None):
        net.vendor = self._vendor(net.bssid)
        with self._lock:
            self.networks[net.bssid] = net
        if cb:
            cb(f'  [+] {net.ssid:25s}  {net.bssid}  '
               f'Ch:{net.channel:3d}  {net.signal:3d}%  [{net.security}]\n')

    def scan(self, cb: Optional[Callable] = None):
        self.is_scanning = True
        def _run():
            if cb:
                cb('\n╔══════════════════════════════╗\n'
                   '║   WiFi Network Scanner       ║\n'
                   '╚══════════════════════════════╝\n\n')
            s = platform.system()
            if   s == 'Windows': self._win(cb)
            elif s == 'Linux':   self._linux(cb)
            elif s == 'Darwin':  self._mac(cb)
            else:
                if cb: cb(f'[!] Unsupported OS: {s}\n')
            self._get_current()
            self.is_scanning = False
            if cb:
                cb(f'\n── {len(self.networks)} networks ──\n\n')
                self._table(cb)
        threading.Thread(target=_run, daemon=True).start()

    def _win(self, cb=None):
        try:
            if cb: cb('[*] Scanning (netsh)...\n')
            r = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='ignore')
            cur = None
            for line in r.stdout.split('\n'):
                line = line.strip()
                if line.startswith('SSID') and ':' in line and 'BSSID' not in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid:
                        cur = WiFiNet(ssid=ssid, bssid='',
                                      first_seen=time.time(), last_seen=time.time())
                elif line.startswith('BSSID') and cur:
                    bssid = line.split(':', 1)[1].strip()
                    # Windows netsh outputs BSSID as space-separated hex: handle
                    cur.bssid = bssid.upper()
                elif ('Authentication' in line or 'Проверка' in line) and cur:
                    auth = line.split(':', 1)[1].strip()
                    if   'WPA3' in auth: cur.security = 'WPA3'
                    elif 'WPA2' in auth: cur.security = 'WPA2'
                    elif 'WPA'  in auth: cur.security = 'WPA'
                    elif 'WEP'  in auth: cur.security = 'WEP'
                    else:                cur.security = 'Open'
                elif ('Signal' in line or 'Сигнал' in line) and cur:
                    m = re.search(r'(\d+)%', line)
                    if m:
                        cur.signal     = int(m.group(1))
                        cur.signal_dbm = int((cur.signal / 2) - 100)
                elif ('Channel' in line or 'Канал' in line) and cur:
                    m = re.search(r'(\d+)', line.split(':', 1)[1] if ':' in line else line)
                    if m:
                        ch = int(m.group(1))
                        cur.channel = ch
                        cur.band    = '2.4 GHz' if ch <= 14 else ('5 GHz' if ch < 133 else '6 GHz')
                if (not line or (line.startswith('SSID') and 'BSSID' not in line)) and cur and cur.bssid:
                    self._add(cur, cb)
                    if not line:
                        cur = None
            if cur and cur.bssid:
                self._add(cur, cb)
        except Exception as e:
            if cb: cb(f'[!] Windows scan: {e}\n')

    def _linux(self, cb=None):
        try:
            if cb: cb('[*] Scanning (nmcli)...\n')
            r = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,FREQ,CHAN,SECURITY',
                 'device', 'wifi', 'list', '--rescan', 'yes'],
                capture_output=True, text=True, timeout=30)
            for line in r.stdout.strip().split('\n'):
                if not line: continue
                try:
                    parts = line.replace('\\:', '§').split(':')
                    if len(parts) >= 6:
                        ssid  = parts[0].replace('§', ':')
                        bssid = parts[1].replace('§', ':').upper()
                        sig   = int(parts[2]) if parts[2].isdigit() else 0
                        freq  = parts[3]
                        ch    = int(parts[4]) if parts[4].isdigit() else 0
                        sec   = parts[5] if len(parts) > 5 else ''
                        net   = WiFiNet(
                            ssid=ssid or '(Hidden)', bssid=bssid,
                            signal=sig, signal_dbm=int((sig / 2) - 100),
                            channel=ch, security=sec or 'Open',
                            hidden=not bool(ssid),
                            first_seen=time.time(), last_seen=time.time())
                        if 'MHz' in freq:
                            m = re.search(r'(\d+)', freq)
                            if m:
                                fv      = int(m.group(1))
                                net.frequency = fv
                                net.band = ('2.4 GHz' if fv < 3000
                                            else ('5 GHz' if fv < 6000 else '6 GHz'))
                        self._add(net, cb)
                except Exception:
                    continue
        except FileNotFoundError:
            self._iwlist(cb)
        except Exception as e:
            if cb: cb(f'[!] Linux: {e}\n')

    def _iwlist(self, cb=None):
        try:
            if cb: cb('[*] Scanning (iwlist)...\n')
            r = subprocess.run(['sudo', 'iwlist', 'wlan0', 'scan'],
                               capture_output=True, text=True, timeout=30)
            cur = None
            for line in r.stdout.split('\n'):
                line = line.strip()
                if 'Cell' in line and 'Address:' in line:
                    if cur and cur.bssid: self._add(cur, cb)
                    bm = re.search(r'([0-9A-Fa-f:]{17})', line)
                    if bm:
                        cur = WiFiNet(ssid='', bssid=bm.group(1).upper(),
                                      first_seen=time.time(), last_seen=time.time())
                elif cur:
                    if 'ESSID:' in line:
                        m = re.search(r'ESSID:"(.*)"', line)
                        if m: cur.ssid = m.group(1) or '(Hidden)'
                    elif 'Channel:' in line:
                        m = re.search(r'Channel:(\d+)', line)
                        if m: cur.channel = int(m.group(1))
                    elif 'Signal level' in line:
                        m = re.search(r'Signal level[=:](-?\d+)', line)
                        if m:
                            cur.signal_dbm = int(m.group(1))
                            cur.signal     = max(0, min(100, (cur.signal_dbm + 100) * 2))
                    elif 'WPA2' in line: cur.security = 'WPA2'
                    elif 'WPA'  in line and cur.security != 'WPA2': cur.security = 'WPA'
                    elif 'Encryption key:on'  in line and cur.security == 'Unknown': cur.security = 'Encrypted'
                    elif 'Encryption key:off' in line: cur.security = 'Open'
            if cur and cur.bssid: self._add(cur, cb)
        except Exception as e:
            if cb: cb(f'[!] iwlist: {e}\n')

    def _mac(self, cb=None):
        try:
            if cb: cb('[*] Scanning (airport)...\n')
            ap = ('/System/Library/PrivateFrameworks/Apple80211.framework'
                  '/Versions/Current/Resources/airport')
            r = subprocess.run([ap, '-s'],
                               capture_output=True, text=True, timeout=15)
            for line in r.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) < 7: continue
                ssid  = parts[0]
                bssid = parts[1].upper()
                rssi  = int(parts[2])
                m     = re.search(r'(\d+)', parts[3])
                ch    = int(m.group(1)) if m else 0
                sec   = ' '.join(parts[6:])
                net   = WiFiNet(
                    ssid=ssid, bssid=bssid,
                    signal=max(0, min(100, (rssi + 100) * 2)),
                    signal_dbm=rssi, channel=ch,
                    security=sec or 'Open',
                    band='2.4 GHz' if ch <= 14 else '5 GHz',
                    first_seen=time.time(), last_seen=time.time())
                self._add(net, cb)
        except Exception as e:
            if cb: cb(f'[!] macOS: {e}\n')

    def _get_current(self):
        try:
            s = platform.system()
            if s == 'Windows':
                r = subprocess.run(
                    ['netsh', 'wlan', 'show', 'interfaces'],
                    capture_output=True, text=True, timeout=5,
                    encoding='utf-8', errors='ignore')
                for line in r.stdout.split('\n'):
                    if 'SSID' in line and 'BSSID' not in line:
                        m = re.search(r':\s*(.+)', line)
                        if m: self.current_ssid = m.group(1).strip()
                    elif 'BSSID' in line:
                        m = re.search(r':\s*(.+)', line)
                        if m: self.current_bssid = m.group(1).strip().upper()
            elif s == 'Linux':
                r = subprocess.run(['iwgetid', '-r'],
                                   capture_output=True, text=True, timeout=5)
                self.current_ssid = r.stdout.strip()
            elif s == 'Darwin':
                ap = ('/System/Library/PrivateFrameworks/Apple80211.framework'
                      '/Versions/Current/Resources/airport')
                r = subprocess.run([ap, '-I'],
                                   capture_output=True, text=True, timeout=5)
                for line in r.stdout.split('\n'):
                    if ' SSID:'  in line: self.current_ssid  = line.split(':')[1].strip()
                    elif 'BSSID:' in line: self.current_bssid = line.split(':', 1)[1].strip().upper()
            for net in self.networks.values():
                if net.bssid == self.current_bssid or net.ssid == self.current_ssid:
                    net.is_connected = True
        except Exception:
            pass

    def _table(self, cb):
        nets = sorted(self.networks.values(), key=lambda n: n.signal_dbm, reverse=True)
        cb(f"  {'SSID':25s}  {'BSSID':18s}  {'Ch':>3s}  {'Signal':>12s}  {'Security':10s}  {'Band'}\n")
        cb(f"  {'─' * 85}\n")
        for n in nets:
            mark = '◀ ' if n.is_connected else '  '
            cb(f'{mark}{n.ssid:25s}  {n.bssid:18s}  {n.channel:3d}  '
               f'{n.bars()} {n.signal_dbm:4d}dBm  {n.security:10s}  {n.band}\n')

    def stop(self):
        self.is_scanning = False

    def clear(self):
        with self._lock:
            self.networks.clear()