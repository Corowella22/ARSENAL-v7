import asyncio
import threading
import time
import platform
import subprocess
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable

try:
    from bleak import BleakScanner, BleakClient
    BLEAK = True
except Exception:
    BLEAK = False

KNOWN_SVC = {
    '0000180a-0000-1000-8000-00805f9b34fb': 'Device Info',
    '0000180d-0000-1000-8000-00805f9b34fb': 'Heart Rate',
    '0000180f-0000-1000-8000-00805f9b34fb': 'Battery',
    '00001812-0000-1000-8000-00805f9b34fb': 'HID',
    '00001800-0000-1000-8000-00805f9b34fb': 'Generic Access',
    '00001801-0000-1000-8000-00805f9b34fb': 'Generic Attribute',
    '0000181a-0000-1000-8000-00805f9b34fb': 'Environmental Sensing',
    '0000181c-0000-1000-8000-00805f9b34fb': 'User Data',
    '00001810-0000-1000-8000-00805f9b34fb': 'Blood Pressure',
}

BT_MFR = {
    0x004C: 'Apple', 0x0006: 'Microsoft', 0x0059: 'Nordic',
    0x00E0: 'Google', 0x0075: 'Samsung',  0x0087: 'Garmin',
    0x0157: 'Xiaomi', 0x0310: 'Huawei',  0x0171: 'Amazon',
    0x038F: 'Bose',  0x012D: 'Sony',     0x02FF: 'Fitbit',
    0x0131: 'Tile',  0x0969: 'Anker',
}

NAME_TYPES = {
    'headphones': ['airpod', 'buds', 'headphone', 'earphone', 'bose', 'beats', 'jbl', 'wf-', 'wh-'],
    'speaker':    ['speaker', 'echo', 'homepod', 'boombox', 'flip'],
    'watch':      ['watch', 'band', 'mi band', 'garmin', 'amazfit', 'fitbit'],
    'keyboard':   ['keyboard', 'k380', 'mx keys'],
    'mouse':      ['mouse', 'mx master', 'trackpad', 'magic mouse'],
    'gamepad':    ['gamepad', 'controller', 'joycon', 'dualsense', 'xbox'],
    'phone':      ['iphone', 'galaxy', 'pixel', 'xiaomi', 'huawei'],
    'computer':   ['macbook', 'imac', 'thinkpad', 'surface'],
    'tablet':     ['ipad', 'tab', 'tablet'],
    'tv':         ['tv', 'roku', 'chromecast', 'fire tv', 'apple tv'],
    'light':      ['bulb', 'light', 'hue', 'govee', 'yeelight'],
    'beacon':     ['beacon', 'tile', 'airtag', 'smarttag'],
    'fitness':    ['fitness', 'tracker', 'charge'],
    'camera':     ['camera', 'gopro', 'insta360'],
    'thermometer':['therm', 'temp', 'ruuvi'],
}


@dataclass
class BTDevice:
    address: str
    name: str = 'Unknown'
    rssi: int = -100
    device_type: str = 'unknown'
    bt_type: str = 'ble'
    manufacturer: str = 'Unknown'
    connectable: bool = False
    service_uuids: List[str] = field(default_factory=list)
    manufacturer_data: Dict[int, bytes] = field(default_factory=dict)
    gatt_services: List[Dict] = field(default_factory=list)
    tx_power: int = 0
    packets_seen: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    x: int = 0
    y: int = 0

    def signal_quality(self) -> str:
        if self.rssi >= -50: return 'Excellent'
        if self.rssi >= -60: return 'Good'
        if self.rssi >= -70: return 'Fair'
        if self.rssi >= -80: return 'Weak'
        return 'Very Weak'

    def est_distance(self) -> float:
        if self.rssi == 0 or self.rssi < -100:
            return -1.0
        tx = self.tx_power if self.tx_power else -59
        return round(10 ** ((tx - self.rssi) / 20.0), 1)


class BluetoothScanner:
    def __init__(self):
        self.devices: Dict[str, BTDevice] = {}
        self.is_scanning: bool = False
        self._lock = threading.Lock()
        self.on_found: Optional[Callable] = None
        self.on_updated: Optional[Callable] = None
        self.on_complete: Optional[Callable] = None

    def _classify(self, name: str, mfr: str) -> str:
        n = name.lower()
        m = mfr.lower()
        for dtype, kws in NAME_TYPES.items():
            if any(k in n for k in kws):
                return dtype
        mfr_map = {
            'apple': 'phone', 'samsung': 'phone', 'google': 'phone',
            'garmin': 'watch', 'fitbit': 'fitness', 'tile': 'beacon',
            'bose': 'headphones', 'sony': 'headphones',
        }
        for k, v in mfr_map.items():
            if k in m:
                return v
        return 'unknown'

    def _process_ble(self, device, adv):
        addr = device.address.upper()
        rssi = getattr(adv, 'rssi', getattr(device, 'rssi', -100))
        with self._lock:
            if addr in self.devices:
                d = self.devices[addr]
                d.rssi        = rssi
                d.last_seen   = time.time()
                d.packets_seen += 1
                if self.on_updated:
                    self.on_updated(d)
                return
            mfr = 'Unknown'
            mfr_data = getattr(adv, 'manufacturer_data', {}) or {}
            for mid in mfr_data:
                if mid in BT_MFR:
                    mfr = BT_MFR[mid]
                    break
            name = device.name or getattr(adv, 'local_name', '') or 'Unknown'
            d = BTDevice(
                address=addr, name=name, rssi=rssi,
                bt_type='ble', manufacturer=mfr,
                tx_power=getattr(adv, 'tx_power', 0) or 0,
                connectable=getattr(device, 'connectable', True),
                service_uuids=list(getattr(adv, 'service_uuids', []) or []),
                manufacturer_data=dict(mfr_data),
                first_seen=time.time(), last_seen=time.time(),
                packets_seen=1,
            )
            d.device_type = self._classify(d.name, d.manufacturer)
            self.devices[addr] = d
        if self.on_found:
            self.on_found(d)

    def _run_loop(self, coro):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(coro)
        except Exception:
            pass
        finally:
            loop.close()

    async def _ble_scan_once(self, duration: int):
        devs = await BleakScanner.discover(timeout=duration, return_adv=True)
        for bd, adv in devs.values():
            self._process_ble(bd, adv)
        if self.on_complete:
            self.on_complete(len(self.devices))

    async def _ble_continuous(self):
        scanner = BleakScanner(detection_callback=self._process_ble)
        await scanner.start()
        while self.is_scanning:
            await asyncio.sleep(1)
        await scanner.stop()

    def start_ble_scan(self, duration: int = 15,
                       continuous: bool = False,
                       cb: Optional[Callable] = None) -> bool:
        if not BLEAK:
            if cb and callable(cb):
                cb('[!] bleak not installed: pip install bleak\n')
            return False
        self.is_scanning = True
        self.on_found = cb if callable(cb) else None

        if continuous:
            t = threading.Thread(target=self._run_loop,
                                  args=(self._ble_continuous(),), daemon=True)
        else:
            t = threading.Thread(target=self._run_loop,
                                  args=(self._ble_scan_once(duration),), daemon=True)
        t.start()
        return True

    def scan_classic(self, duration: int = 10, cb: Optional[Callable] = None):
        def _run():
            self.is_scanning = True
            if platform.system() == 'Linux':
                try:
                    if cb: cb('[*] Classic BT scan (hcitool)...\n')
                    result = subprocess.run(
                        ['hcitool', 'scan', '--length', str(max(duration, 5))],
                        capture_output=True, text=True, timeout=duration + 10)
                    for line in result.stdout.strip().split('\n'):
                        m = re.match(r'\s+([0-9A-Fa-f:]{17})\s+(.*)', line)
                        if m:
                            addr = m.group(1).upper()
                            name = m.group(2).strip()
                            with self._lock:
                                if addr not in self.devices:
                                    d = BTDevice(
                                        address=addr, name=name or 'Unknown',
                                        bt_type='classic',
                                        first_seen=time.time(), last_seen=time.time())
                                    d.device_type = self._classify(d.name, d.manufacturer)
                                    self.devices[addr] = d
                                    if cb: cb(f'  [+] {name} ({addr})\n')
                                else:
                                    self.devices[addr].bt_type = 'dual'
                except Exception as e:
                    if cb: cb(f'[!] hcitool: {e}\n')

            elif platform.system() == 'Windows':
                try:
                    import json
                    result = subprocess.run(
                        ['powershell', '-Command',
                         'Get-PnpDevice -Class Bluetooth | '
                         'Select-Object FriendlyName,InstanceId | ConvertTo-Json'],
                        capture_output=True, text=True, timeout=15)
                    if result.stdout.strip():
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]
                        for item in data:
                            name = item.get('FriendlyName', 'Unknown')
                            iid  = item.get('InstanceId', '')
                            mm   = re.search(r'([0-9A-F]{12})', iid)
                            if mm:
                                raw  = mm.group(1)
                                addr = ':'.join(raw[i:i+2] for i in range(0, 12, 2))
                                with self._lock:
                                    if addr not in self.devices:
                                        d = BTDevice(
                                            address=addr, name=name,
                                            bt_type='classic',
                                            first_seen=time.time(), last_seen=time.time())
                                        d.device_type = self._classify(d.name, d.manufacturer)
                                        self.devices[addr] = d
                                        if cb: cb(f'  [+] {name} ({addr})\n')
                except Exception as e:
                    if cb: cb(f'[!] Windows BT: {e}\n')

            self.is_scanning = False
            if self.on_complete:
                self.on_complete(len(self.devices))

        threading.Thread(target=_run, daemon=True).start()

    def connect_device(self, address: str, cb: Optional[Callable] = None):
        if not BLEAK:
            if cb: cb('[!] bleak not installed\n')
            return

        async def _read():
            try:
                if cb: cb(f'[*] Connecting to {address}...\n')
                async with BleakClient(address, timeout=15) as client:
                    if not client.is_connected:
                        if cb: cb('[!] Failed to connect\n')
                        return
                    if cb: cb('[+] Connected!\n')
                    services = []
                    for svc in client.services:
                        sname = KNOWN_SVC.get(str(svc.uuid), str(svc.uuid))
                        if cb: cb(f'  📦 Service: {sname}\n')
                        svc_info = {'uuid': str(svc.uuid), 'name': sname, 'chars': []}
                        for ch in svc.characteristics:
                            ci = {'uuid': str(ch.uuid), 'props': list(ch.properties), 'value': None}
                            if 'read' in ch.properties:
                                try:
                                    val = await client.read_gatt_char(ch.uuid)
                                    ci['value'] = val.hex()
                                    try:
                                        tv = val.decode('utf-8', errors='ignore')
                                        if tv.isprintable() and tv.strip():
                                            ci['text'] = tv
                                    except Exception:
                                        pass
                                except Exception:
                                    ci['value'] = '(unreadable)'
                            vdisp = ci.get('text', ci.get('value', 'N/A'))
                            props = ', '.join(ch.properties)
                            if cb: cb(f'    ├─ {ch.uuid}\n    │  [{props}] = {vdisp}\n')
                            svc_info['chars'].append(ci)
                        services.append(svc_info)
                    with self._lock:
                        if address in self.devices:
                            self.devices[address].gatt_services = services
                    if cb: cb(f'\n[+] {len(services)} services read\n')
            except Exception as e:
                if cb: cb(f'[!] Error: {e}\n')

        threading.Thread(target=self._run_loop, args=(_read(),), daemon=True).start()

    def full_scan(self, ble_dur: int = 10, classic_dur: int = 8,
                  cb: Optional[Callable] = None):
        def _run():
            if cb: cb('\n╔══════════════════════════════╗\n'
                      '║   Bluetooth Full Scan        ║\n'
                      '╚══════════════════════════════╝\n\n')
            if BLEAK:
                if cb: cb('── BLE Phase ──\n')

                def _on_found(d):
                    if cb:
                        dist = d.est_distance()
                        ds   = f'~{dist}m' if dist > 0 else '?'
                        cb(f'  [BLE] {d.address}  "{d.name}"  '
                           f'{d.rssi}dBm  {ds}  [{d.device_type}]\n')

                self.on_found = _on_found
                self._run_loop(self._ble_scan_once(ble_dur))

            if cb: cb('\n── Classic Phase ──\n')
            evt = threading.Event()
            orig = self.on_complete
            self.on_complete = lambda n: evt.set()
            self.scan_classic(classic_dur, cb=cb)
            evt.wait(timeout=classic_dur + 5)
            self.on_complete = orig

            if cb:
                cb(f'\n── Complete: {len(self.devices)} devices ──\n\n')
                for addr, d in sorted(self.devices.items(),
                                       key=lambda x: x[1].rssi, reverse=True):
                    dist = d.est_distance()
                    ds   = f'~{dist}m' if dist > 0 else '?'
                    cb(f'  {addr}  {d.name:22s}  {d.rssi:4d}dBm  '
                       f'{d.signal_quality():10s}  {ds}  [{d.bt_type}]  [{d.device_type}]\n')
                cb('\n')
            self.is_scanning = False

        self.is_scanning = True
        threading.Thread(target=_run, daemon=True).start()

    def start_monitor(self, cb: Optional[Callable] = None):
        def _on_dev(d):
            if cb:
                import time as t
                dist = d.est_distance()
                ds   = f'~{dist}m' if dist > 0 else '?'
                cb(f'[{t.strftime("%H:%M:%S")}] {d.address}  '
                   f'"{d.name}"  {d.rssi}dBm  ({d.signal_quality()})  {ds}  [{d.device_type}]\n')

        self.on_found   = _on_dev
        self.on_updated = _on_dev
        if cb: cb('[*] BT Monitor — tracking advertisements...\n\n')
        self.start_ble_scan(duration=0, continuous=True)

    def stop(self):
        self.is_scanning = False

    def clear(self):
        with self._lock:
            self.devices.clear()