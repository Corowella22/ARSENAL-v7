import json
import platform
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk
from PIL import ImageTk

from styles import C, F, DEVICE_LABELS, PROTO_COLORS
from scanner import NetworkScanner, Device
from sniffer import TrafficSniffer
from power_control import PowerController, PowerAction
from bluetooth_module import BluetoothScanner
from wifi_module import WiFiScanner
from device_icons import IconRenderer


class NetMapApp(ctk.CTk):
    def __init__(self, has_root: bool = False):
        super().__init__()
        self.title('ARSENAL v 7.0')
        self.geometry('1450x900')
        self.minsize(1200, 700)
        self.configure(fg_color=C['bg'])

        self.scanner  = NetworkScanner()
        self.sniffer  = TrafficSniffer()
        self.power    = PowerController()
        self.bt       = BluetoothScanner()
        self.wifi     = WiFiScanner()
        self.icons    = IconRenderer(64)
        self.has_root = has_root

        self.selected_ip: str  = ''
        self.net_info: dict    = {}
        self.tk_imgs: dict     = {}
        self._ssh_client       = None
        self._map_drag: dict   = {'ip': None, 'x': 0, 'y': 0}

        self._build_ui()
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        self.after(600, self._init_net)

   
    def _build_ui(self):
        self._menu_bar()
        self._toolbar()
        self._setup_styles()

        main = ctk.CTkFrame(self, fg_color=C['bg'])
        main.pack(fill='both', expand=True, padx=1, pady=1)
        pw = tk.PanedWindow(main, orient='horizontal', bg=C['bg'], sashwidth=4)
        pw.pack(fill='both', expand=True)

        self._left_panel(pw)
        self._center_panel(pw)
        self._right_panel(pw)
        self._status_bar()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        for name in ('Dev.Treeview', 'BT.Treeview', 'WiFi.Treeview', 'Pkt.Treeview'):
            style.configure(name,
                background=C['bg'], foreground=C['text2'],
                fieldbackground=C['bg'], borderwidth=0,
                font=F['body'], rowheight=46)
            style.configure(f'{name}.Heading',
                background=C['panel2'], foreground=C['teal'],
                font=('Consolas', 9, 'bold'))
            style.map(name,
                background=[('selected', C['select'])],
                foreground=[('selected', C['text'])])
        for name in ('BT.Treeview', 'WiFi.Treeview', 'Pkt.Treeview'):
            style.configure(name, rowheight=24, font=F['mono_s'])

    #menu bar 
    def _menu_bar(self):
        f = ctk.CTkFrame(self, height=30, fg_color=C['panel'], corner_radius=0)
        f.pack(fill='x')
        f.pack_propagate(False)
        ctk.CTkLabel(f, text='  ARSENAL V 6.0',
                     font=('Cascadia Code', 14, 'bold'),
                     text_color=C['teal']).pack(side='left', padx=5)
        ctk.CTkLabel(f, text=' │ ', text_color=C['border']).pack(side='left')
        for name in ('File', 'Scan', 'Help'):
            ctk.CTkButton(f, text=name, font=F['body'],
                          fg_color='transparent', hover_color=C['hover'],
                          width=50, height=24,
                          command=lambda n=name: self._menu(n)).pack(side='left', padx=1)
        lbl = 'ROOT' if self.has_root else 'USER'
        clr = C['green'] if self.has_root else C['orange']
        ctk.CTkLabel(f, text=lbl, font=F['status'],
                     text_color=clr).pack(side='right', padx=10)

    
    def _toolbar(self):
        tb = ctk.CTkFrame(self, height=45, fg_color=C['panel2'], corner_radius=0)
        tb.pack(fill='x')
        tb.pack_propagate(False)
        items = [
            ('Quick Scan', self._quick_scan, C['blue']),
            ('Deep Scan',  self._deep_scan,  C['purple']),
            ('Stop',        self._stop_all,   C['red']),
            None,
            ('Capture',    self._toggle_sniff, C['green']),
            ('Export',     self._save,        C['orange']),
            None,
            ('Clear',      self._clear_all,   C['gray']),
        ]
        for item in items:
            if item is None:
                ctk.CTkFrame(tb, width=2, height=28,
                             fg_color=C['border']).pack(side='left', padx=6, pady=8)
                continue
            text, cmd, clr = item
            ctk.CTkButton(tb, text=text, font=F['mono_s'],
                          fg_color=C['bg2'], hover_color=C['hover'],
                          border_width=1, border_color=clr,
                          width=115, height=30, command=cmd).pack(side='left', padx=3, pady=7)

    # left panel
    def _left_panel(self, pw):
        p = ctk.CTkFrame(pw, fg_color=C['panel'], width=280, corner_radius=0)
        pw.add(p, minsize=250)

        h = ctk.CTkFrame(p, height=32, fg_color=C['panel2'], corner_radius=0)
        h.pack(fill='x')
        h.pack_propagate(False)
        ctk.CTkLabel(h, text='Devices', font=F['panel'],
                     text_color=C['teal']).pack(side='left', padx=5)
        self.dev_count = ctk.CTkLabel(h, text='(0)', font=F['small'],
                                       text_color=C['text4'])
        self.dev_count.pack(side='right', padx=10)

        self.search_var = tk.StringVar()
        self.search_var.trace('w', self._filter_devs)
        ctk.CTkEntry(p, textvariable=self.search_var,
                     placeholder_text='🔍 Filter...',
                     font=F['mono_s'], fg_color=C['input'],
                     border_color=C['border'], height=26).pack(fill='x', padx=5, pady=5)

        tf = ctk.CTkFrame(p, fg_color=C['bg'])
        tf.pack(fill='both', expand=True, padx=5, pady=(0, 5))

        self.dev_tree = ttk.Treeview(tf, columns=('v',), show='tree',
                                      style='Dev.Treeview', selectmode='browse')
        self.dev_tree.column('#0', width=240)
        self.dev_tree.column('v', width=0, stretch=False)
        sc = ttk.Scrollbar(tf, orient='vertical', command=self.dev_tree.yview)
        self.dev_tree.configure(yscrollcommand=sc.set)
        self.dev_tree.pack(side='left', fill='both', expand=True)
        sc.pack(side='right', fill='y')
        self.dev_tree.bind('<<TreeviewSelect>>', self._on_dev_sel)
        self.dev_tree.bind('<Double-1>', self._on_dev_dbl)

    # panel
    def _center_panel(self, pw):
        c = ctk.CTkFrame(pw, fg_color=C['bg'], corner_radius=0)
        pw.add(c, minsize=500)
        self.tabs = ctk.CTkTabview(c, fg_color=C['bg'],
                                    segmented_button_fg_color=C['panel2'],
                                    segmented_button_selected_color=C['blue'],
                                    segmented_button_unselected_color=C['panel'])
        self.tabs.pack(fill='both', expand=True, padx=2, pady=2)
        self._tab_map(self.tabs.add('Map'))
        self._tab_traffic(self.tabs.add('Traffic'))
        self._tab_console(self.tabs.add('Console'))
        self._tab_ports(self.tabs.add('Ports'))
        self._tab_bt(self.tabs.add('Bluetooth'))
        self._tab_wifi(self.tabs.add('WiFi'))

    #кшпре зфтуд
    def _right_panel(self, pw):
        p = ctk.CTkFrame(pw, fg_color=C['panel'], width=320, corner_radius=0)
        pw.add(p, minsize=280)
        h = ctk.CTkFrame(p, height=32, fg_color=C['panel2'], corner_radius=0)
        h.pack(fill='x')
        h.pack_propagate(False)
        ctk.CTkLabel(h, text='Details', font=F['panel'],
                     text_color=C['teal']).pack(side='left', padx=5)
        self.detail_scroll = ctk.CTkScrollableFrame(p, fg_color=C['panel'])
        self.detail_scroll.pack(fill='both', expand=True, padx=2, pady=2)
        self._details_placeholder()

    def _details_placeholder(self):
        for w in self.detail_scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.detail_scroll,
                     text='\n\n made by Corowella22\n\n'
                          'ENTOPY TEAM',
                     font=F['body'], text_color=C['text4'],
                     justify='center').pack(pady=80)

    # status
    def _status_bar(self):
        sb = ctk.CTkFrame(self, height=28, fg_color=C['panel2'], corner_radius=0)
        sb.pack(fill='x', side='bottom')
        sb.pack_propagate(False)
        self.status_lbl = ctk.CTkLabel(sb, text='Ready',
                                        font=F['status'], text_color=C['text4'])
        self.status_lbl.pack(side='left', padx=5)
        self.progress = ctk.CTkProgressBar(sb, width=180, height=10,
                                            fg_color=C['bg'],
                                            progress_color=C['blue'])
        self.progress.pack(side='right', padx=10, pady=9)
        self.progress.set(0)
        self.net_lbl = ctk.CTkLabel(sb, text='', font=F['status'],
                                     text_color=C['text4'])
        self.net_lbl.pack(side='right', padx=10)

    
    def _tab_map(self, parent):
        self.map_canvas = tk.Canvas(parent, bg=C['bg'], highlightthickness=0)
        self.map_canvas.pack(fill='both', expand=True)
        self.map_canvas.bind('<Configure>', self._draw_grid)
        self.map_canvas.bind('<Button-1>', self._map_press)
        self.map_canvas.bind('<B1-Motion>', self._map_drag_move)
        self.map_canvas.bind('<ButtonRelease-1>', self._map_release)
        self.map_canvas.bind('<Double-Button-1>', self._map_dblclick)

    def _tab_traffic(self, parent):
        ctrl = ctk.CTkFrame(parent, height=38, fg_color=C['panel'])
        ctrl.pack(fill='x', padx=2, pady=2)
        ctrl.pack_propagate(False)
        self.sniff_lbl = ctk.CTkLabel(ctrl, text='Stopped',
                                       font=F['mono_s'], text_color=C['red'])
        self.sniff_lbl.pack(side='left', padx=10)
        ctk.CTkLabel(ctrl, text='BPF:', font=F['mono_s'],
                     text_color=C['text4']).pack(side='left', padx=3)
        self.bpf_var = tk.StringVar()
        ctk.CTkEntry(ctrl, textvariable=self.bpf_var,
                     placeholder_text='e.g. tcp port 80',
                     font=F['mono_s'], fg_color=C['input'],
                     width=220, height=26).pack(side='left', padx=5)
        self.pkt_stats_lbl = ctk.CTkLabel(ctrl, text='0 pkts',
                                           font=F['mono_s'], text_color=C['text4'])
        self.pkt_stats_lbl.pack(side='right', padx=10)

        pf = ctk.CTkFrame(parent, fg_color=C['bg'])
        pf.pack(fill='both', expand=True, padx=2, pady=2)
        cols = ('time', 'src', 'dst', 'proto', 'len', 'info')
        self.pkt_tree = ttk.Treeview(pf, columns=cols, show='headings',
                                      style='Pkt.Treeview')
        ws  = {'time': 85, 'src': 125, 'dst': 125, 'proto': 65, 'len': 50, 'info': 400}
        nms = {'time': 'Time', 'src': 'Source', 'dst': 'Dest',
               'proto': 'Proto', 'len': 'Len', 'info': 'Info'}
        for col in cols:
            self.pkt_tree.heading(col, text=nms[col])
            self.pkt_tree.column(col, width=ws[col])
        ps = ttk.Scrollbar(pf, orient='vertical', command=self.pkt_tree.yview)
        self.pkt_tree.configure(yscrollcommand=ps.set)
        self.pkt_tree.pack(side='left', fill='both', expand=True)
        ps.pack(side='right', fill='y')
        for proto, clr in PROTO_COLORS.items():
            self.pkt_tree.tag_configure(proto, foreground=clr)

    def _tab_console(self, parent):
        conn = ctk.CTkFrame(parent, height=38, fg_color=C['panel'])
        conn.pack(fill='x', padx=2, pady=2)
        conn.pack_propagate(False)
        fields = [('Host:', 'con_ip', '', 140, ''),
                  ('User:', 'con_user', 'root', 90, ''),
                  ('Pass:', 'con_pass', '', 90, '*')]
        for lbl, attr, default, w, show in fields:
            ctk.CTkLabel(conn, text=lbl, font=F['mono_s'],
                         text_color=C['text4']).pack(side='left', padx=3)
            var = tk.StringVar(value=default)
            setattr(self, f'{attr}_var', var)
            ctk.CTkEntry(conn, textvariable=var, font=F['mono_s'],
                         fg_color=C['input'], width=w, height=26,
                         show=show).pack(side='left', padx=3)
        ctk.CTkButton(conn, text='SSH', font=F['mono_s'],
                      fg_color=C['green'], width=80, height=26,
                      command=self._ssh_connect).pack(side='left', padx=5)
        ctk.CTkButton(conn, text='❌', font=F['mono_s'],
                      fg_color=C['red'], width=40, height=26,
                      command=self._ssh_disconnect).pack(side='left', padx=3)

        self.console = tk.Text(parent, bg=C['con_bg'], fg=C['con_fg'],
                               font=F['mono'], insertbackground=C['prompt'],
                               selectbackground=C['select'],
                               wrap='word', padx=10, pady=10)
        self.console.pack(fill='both', expand=True, padx=2, pady=2)
        self.console.tag_configure('prompt', foreground=C['prompt'])
        self.console.tag_configure('err',    foreground=C['red'])
        self.console.tag_configure('info',   foreground=C['teal'])

        inp = ctk.CTkFrame(parent, height=35, fg_color=C['panel'])
        inp.pack(fill='x', padx=2, pady=2)
        inp.pack_propagate(False)
        ctk.CTkLabel(inp, text=' $', font=F['mono_b'],
                     text_color=C['prompt']).pack(side='left', padx=3)
        self.cmd_var = tk.StringVar()
        self.cmd_entry = ctk.CTkEntry(inp, textvariable=self.cmd_var,
                                       font=F['mono'], fg_color=C['input'],
                                       border_color=C['prompt'], height=26)
        self.cmd_entry.pack(side='left', fill='x', expand=True, padx=5)
        self.cmd_entry.bind('<Return>', self._run_cmd)
        ctk.CTkButton(inp, text='▶', font=F['mono'],
                      fg_color=C['blue'], width=40, height=26,
                      command=lambda: self._run_cmd(None)).pack(side='right', padx=5)

       
    def _tab_ports(self, parent):
        ctrl = ctk.CTkFrame(parent, height=38, fg_color=C['panel'])
        ctrl.pack(fill='x', padx=2, pady=2)
        ctrl.pack_propagate(False)
        ctk.CTkLabel(ctrl, text='Target:', font=F['mono_s'],
                     text_color=C['text4']).pack(side='left', padx=5)
        self.port_ip_var = tk.StringVar()
        ctk.CTkEntry(ctrl, textvariable=self.port_ip_var,
                     font=F['mono_s'], fg_color=C['input'],
                     width=140, height=26).pack(side='left', padx=5)
        ctk.CTkLabel(ctrl, text='Ports:', font=F['mono_s'],
                     text_color=C['text4']).pack(side='left', padx=5)
        self.port_range_var = tk.StringVar(value='1-1024')
        ctk.CTkEntry(ctrl, textvariable=self.port_range_var,
                     font=F['mono_s'], fg_color=C['input'],
                     width=100, height=26).pack(side='left', padx=5)
        ctk.CTkButton(ctrl, text='Scan', font=F['mono_s'],
                      fg_color=C['blue'], width=90, height=26,
                      command=self._port_scan).pack(side='left', padx=10)

        self.port_out = tk.Text(parent, bg=C['bg'], fg=C['text2'],
                                font=F['mono'], wrap='word', padx=10, pady=10)
        self.port_out.pack(fill='both', expand=True, padx=2, pady=2)
        self.port_out.tag_configure('open', foreground=C['green'])
        self.port_out.tag_configure('hdr',  foreground=C['teal'], font=F['mono_b'])
        self.port_out.tag_configure('dim',  foreground=C['text4'])

    def _tab_bt(self, parent):
        ctrl = ctk.CTkFrame(parent, height=40, fg_color=C['panel'])
        ctrl.pack(fill='x', padx=2, pady=2)
        ctrl.pack_propagate(False)
        for text, cmd, clr in (('BLE', self._bt_ble, C['blue']),
                               ('Classic', self._bt_classic, C['purple']),
                               ('Full', self._bt_full, C['green']),
                               ('Monitor', self._bt_monitor, C['orange']),
                               ('Stop', self.bt.stop, C['red'])):
            ctk.CTkButton(ctrl, text=text, font=F['mono_s'],
                          fg_color=C['bg2'], hover_color=clr,
                          border_width=1, border_color=clr,
                          width=90, height=28, command=cmd).pack(side='left', padx=3, pady=6)
        self.bt_count_lbl = ctk.CTkLabel(ctrl, text='0 devices',
                                          font=F['mono_s'], text_color=C['text4'])
        self.bt_count_lbl.pack(side='right', padx=10)

        sp = tk.PanedWindow(parent, orient='horizontal', bg=C['bg'], sashwidth=3)
        sp.pack(fill='both', expand=True, padx=2, pady=2)
        lf = ctk.CTkFrame(sp, fg_color=C['bg'])
        sp.add(lf, minsize=300)
        bcols = ('addr', 'name', 'rssi', 'type', 'dist', 'mfr')
        self.bt_tree = ttk.Treeview(lf, columns=bcols, show='headings',
                                     style='BT.Treeview')
        bh = {'addr':('Address',140),'name':('Name',140),'rssi':('RSSI',55),
              'type':('Type',85),'dist':('Dist',50),'mfr':('Vendor',100)}
        for col, (title, w) in bh.items():
            self.bt_tree.heading(col, text=title)
            self.bt_tree.column(col, width=w)
        bs = ttk.Scrollbar(lf, orient='vertical', command=self.bt_tree.yview)
        self.bt_tree.configure(yscrollcommand=bs.set)
        self.bt_tree.pack(side='left', fill='both', expand=True)
        bs.pack(side='right', fill='y')
        self.bt_tree.bind('<Double-1>', self._bt_connect)
        for tag, clr in (('excellent','#2ECC71'),('good','#82E0AA'),
                          ('fair','#F4D03F'),('weak','#E67E22'),('very_weak','#E74C3C')):
            self.bt_tree.tag_configure(tag, foreground=clr)
        rf = ctk.CTkFrame(sp, fg_color=C['bg'])
        sp.add(rf, minsize=300)
        self.bt_out = tk.Text(rf, bg=C['con_bg'], fg=C['con_fg'],
                              font=F['mono'], wrap='word', padx=8, pady=8)
        self.bt_out.pack(fill='both', expand=True)
        self.bt_out.tag_configure('info',  foreground=C['teal'])
        self.bt_out.tag_configure('found', foreground=C['green'])

    def _tab_wifi(self, parent):
        ctrl = ctk.CTkFrame(parent, height=40, fg_color=C['panel'])
        ctrl.pack(fill='x', padx=2, pady=2)
        ctrl.pack_propagate(False)
        ctk.CTkButton(ctrl, text='Scan WiFi', font=F['mono_s'],
                      fg_color=C['blue'], width=120, height=28,
                      command=self._wifi_scan).pack(side='left', padx=5, pady=6)
        ctk.CTkButton(ctrl, text='⏹ Stop', font=F['mono_s'],
                      fg_color=C['red'], width=70, height=28,
                      command=self.wifi.stop).pack(side='left', padx=3)
        self.wifi_count_lbl = ctk.CTkLabel(ctrl, text='0 networks',
                                            font=F['mono_s'], text_color=C['text4'])
        self.wifi_count_lbl.pack(side='right', padx=10)

        sp = tk.PanedWindow(parent, orient='horizontal', bg=C['bg'], sashwidth=3)
        sp.pack(fill='both', expand=True, padx=2, pady=2)
        lf = ctk.CTkFrame(sp, fg_color=C['bg'])
        sp.add(lf, minsize=450)
        wcols = ('ssid','bssid','ch','signal','security','band','vendor')
        self.wifi_tree = ttk.Treeview(lf, columns=wcols, show='headings',
                                       style='WiFi.Treeview')
        wh = {'ssid':('SSID',160),'bssid':('BSSID',130),'ch':('Ch',35),
              'signal':('Signal',90),'security':('Security',80),
              'band':('Band',60),'vendor':('Vendor',90)}
        for col, (title, w) in wh.items():
            self.wifi_tree.heading(col, text=title)
            self.wifi_tree.column(col, width=w)
        ws = ttk.Scrollbar(lf, orient='vertical', command=self.wifi_tree.yview)
        self.wifi_tree.configure(yscrollcommand=ws.set)
        self.wifi_tree.pack(side='left', fill='both', expand=True)
        ws.pack(side='right', fill='y')
        for tag, clr in (('open','#E74C3C'),('wep','#E67E22'),
                          ('wpa','#F4D03F'),('wpa2','#2ECC71'),
                          ('wpa3','#3498DB'),('connected','#00E5FF')):
            self.wifi_tree.tag_configure(tag, foreground=clr)
        rf = ctk.CTkFrame(sp, fg_color=C['bg'])
        sp.add(rf, minsize=250)
        self.wifi_out = tk.Text(rf, bg=C['con_bg'], fg=C['con_fg'],
                                font=F['mono'], wrap='word', padx=8, pady=8)
        self.wifi_out.pack(fill='both', expand=True)
        self.wifi_out.tag_configure('info', foreground=C['teal'])

   #helpers
    def _set_status(self, text: str, clr: str = None):
        self.status_lbl.configure(text=f'  {text}', text_color=clr or C['text4'])

    def _init_net(self):
        def _r():
            info = self.scanner.get_network_info()
            self.net_info = info
            self.after(0, lambda: self.net_lbl.configure(
                text=f"IP:{info['local_ip']}  GW:{info['gateway']}  Net:{info['subnet']}"))
        threading.Thread(target=_r, daemon=True).start()

    def _menu(self, name: str):
        if name == 'Help':
            messagebox.showinfo('About',
                'NetMap Pro v3.0\n\nNetwork Analysis Tool\n'
                'Cisco PT Style\n\n Use on YOUR networks only.')
        elif name == 'File':
            self._save()


    def _quick_scan(self):
        self._set_status('Quick scan...', C['blue'])
        self.progress.set(0)
        def _r():
            self.scanner.full_scan(port_scan=False, progress_cb=self._scan_progress)
            self.after(0, self._post_scan)
        threading.Thread(target=_r, daemon=True).start()

    def _deep_scan(self):
        self._set_status('Deep scan...', C['purple'])
        self.progress.set(0)
        def _r():
            self.scanner.full_scan(port_scan=True, progress_cb=self._scan_progress)
            self.after(0, self._post_scan)
        threading.Thread(target=_r, daemon=True).start()

    def _scan_progress(self, pct: int, msg: str):
        self.after(0, lambda: [
            self.progress.set(pct / 100),
            self._set_status(f'🔄 {msg} ({pct}%)', C['blue'])
        ])

    def _stop_all(self):
        self.scanner.stop_scan()
        self.sniffer.stop()
        self.bt.stop()
        self.wifi.stop()
        self._set_status('Stopped', C['orange'])
        self.sniff_lbl.configure(text='Stopped', text_color=C['red'])

    def _post_scan(self):
        devs = self.scanner.devices
        n    = len(devs)
        self._set_status(f'✅ {n} devices found', C['green'])
        self.progress.set(1.0)
        self.dev_count.configure(text=f'({n})')
        self._fill_tree(devs)
        self._draw_map()

   
    def _fill_tree(self, devs: dict):
        self.dev_tree.delete(*self.dev_tree.get_children())
        groups: dict = {}
        for ip, d in devs.items():
            groups.setdefault(d.device_type, []).append(d)
        order = ['router','gateway','wireless_ap','switch','server',
                 'computer','laptop','phone','printer','iot','unknown']
        for dt in order:
            if dt not in groups: continue
            lbl = DEVICE_LABELS.get(dt, dt).upper()
            gid = self.dev_tree.insert('', 'end',
                                        text=f' {lbl} ({len(groups[dt])})',
                                        open=True)
            for d in sorted(groups[dt], key=lambda x: x.ip):
                st  = '' if d.status == 'online' else ''
                txt = f' {st} {d.ip}\n    {d.hostname[:22]}'
                if d.vendor != 'Unknown':
                    txt += f'\n    [{d.vendor[:20]}]'
                self.dev_tree.insert(gid, 'end', text=txt,
                                      values=(d.ip,), tags=(d.ip,))

    def _filter_devs(self, *_):
        ft = self.search_var.get().lower()
        if not ft:
            self._fill_tree(self.scanner.devices)
            return
        filtered = {ip: d for ip, d in self.scanner.devices.items()
                    if any(ft in s.lower() for s in
                           [ip, d.hostname, d.vendor, d.device_type, d.mac])}
        self._fill_tree(filtered)

    def _on_dev_sel(self, _=None):
        sel = self.dev_tree.selection()
        if not sel: return
        vals = self.dev_tree.item(sel[0], 'values')
        if vals and vals[0]:
            self.selected_ip = vals[0]
            self._show_details(vals[0])

    def _on_dev_dbl(self, _=None):
        self._on_dev_sel()
        if self.selected_ip:
            self.con_ip_var.set(self.selected_ip)
            self.port_ip_var.set(self.selected_ip)

   
    def _draw_grid(self, event=None):
        self.map_canvas.delete('grid')
        w = max(self.map_canvas.winfo_width(),  800)
        h = max(self.map_canvas.winfo_height(), 600)
        for x in range(0, w+30, 30):
            self.map_canvas.create_line(x, 0, x, h, fill=C['grid'], dash=(1,6), tags='grid')
        for y in range(0, h+30, 30):
            self.map_canvas.create_line(0, y, w, y, fill=C['grid'], dash=(1,6), tags='grid')

    def _draw_map(self):
        self.map_canvas.delete('dev')
        self.map_canvas.delete('link')
        self.map_canvas.delete('lbl')
        self.tk_imgs.clear()
        devs  = self.scanner.devices
        if not devs: return
        w = max(self.map_canvas.winfo_width(),  800)
        h = max(self.map_canvas.winfo_height(), 600)
        gw_ip = self.scanner.gateway_ip

        layer_map = {
            'cloud':0,'firewall':1,'router':1,'gateway':1,
            'wireless_ap':2,'switch':2,
            'server':3,'computer':3,'laptop':3,
            'phone':3,'printer':3,'camera':3,'iot':3,'unknown':3,
        }
        layers: dict = {0:[],1:[],2:[],3:[]}
        for ip, d in devs.items():
            layer = layer_map.get(d.device_type, 3)
            if d.is_gateway: layer = 1
            layers[layer].append(ip)

        positions: dict = {}
        cy = 70
        for ln in sorted(layers):
            ld = layers[ln]
            if not ld: continue
            n = len(ld)
            for i, ip in enumerate(ld):
                if n == 1:
                    px = w // 2
                else:
                    sp = min(140, (w - 160) // max(n-1, 1))
                    px = (w - (n-1)*sp) // 2 + i*sp
                px = max(60, min(w-60, px))
                positions[ip] = (px, cy)
                devs[ip].x = px
                devs[ip].y = cy
            cy += 160
#links
        gp = positions.get(gw_ip)
        if gp:
            for ip, pos in positions.items():
                if ip == gw_ip: continue
                d  = devs[ip]
                lc = C['link_on'] if d.status == 'online' else C['link_off']
                self.map_canvas.create_line(gp[0], gp[1], pos[0], pos[1],
                                            fill=lc, width=2, dash=(8,4), tags='link')
                if d.latency > 0:
                    mx = (gp[0]+pos[0])//2
                    my = (gp[1]+pos[1])//2
                    self.map_canvas.create_text(mx, my-8,
                                                text=f'{d.latency:.0f}ms',
                                                font=F['tiny'], fill=C['text4'],
                                                tags='link')

     
        for ip, (x, y) in positions.items():
            d   = devs[ip]
            img = self.icons.get(d.device_type, 64, d.status)
            tki = ImageTk.PhotoImage(img)
            self.tk_imgs[ip] = tki
            self.map_canvas.create_image(x, y, image=tki, tags=(f'd_{ip}', 'dev'))

            if ip == self.scanner.local_ip:
                self.map_canvas.create_oval(x-38, y-38, x+38, y+38,
                                            outline=C['teal'], width=2, dash=(4,4),
                                            tags=(f'd_{ip}', 'dev'))
            if d.is_gateway:
                self.map_canvas.create_oval(x+24, y-28, x+40, y-12,
                                            fill=C['orange'], outline='white',
                                            tags=(f'd_{ip}', 'dev'))
                self.map_canvas.create_text(x+32, y-20, text='GW',
                                            font=('Consolas', 6, 'bold'),
                                            fill='white', tags=(f'd_{ip}', 'dev'))
            hn  = d.hostname if (d.hostname != 'Unknown' and len(d.hostname) <= 18) else ip
            ly  = y + 42
            lbl = DEVICE_LABELS.get(d.device_type, d.device_type)
            self.map_canvas.create_text(x, ly, text=hn,
                                        font=F['dev_n'], fill=C['text'],
                                        tags=(f'd_{ip}', 'dev', 'lbl'))
            self.map_canvas.create_text(x, ly+14, text=ip,
                                        font=F['dev_i'], fill=C['text3'],
                                        tags=(f'd_{ip}', 'dev', 'lbl'))
            self.map_canvas.create_text(x, ly+26, text=f'[{lbl}]',
                                        font=F['dev_t'], fill=C['teal'],
                                        tags=(f'd_{ip}', 'dev', 'lbl'))

        self.map_canvas.create_text(15, 12,
                                    text=f'◆ Topology — {len(devs)} devices',
                                    font=F['map_b'], fill=C['teal'],
                                    anchor='nw', tags='lbl')

    def _find_dev(self, x: int, y: int) -> str:
        for item in self.map_canvas.find_overlapping(x-8, y-8, x+8, y+8):
            for tag in self.map_canvas.gettags(item):
                if tag.startswith('d_'):
                    return tag[2:]
        return ''

    def _map_press(self, e):
        ip = self._find_dev(e.x, e.y)
        if ip:
            self._map_drag = {'ip': ip, 'x': e.x, 'y': e.y}
            self.selected_ip = ip
            self._show_details(ip)
        else:
            self._map_drag = {'ip': None, 'x': 0, 'y': 0}

    def _map_drag_move(self, e):
        ip = self._map_drag.get('ip')
        if not ip: return
        dx = e.x - self._map_drag['x']
        dy = e.y - self._map_drag['y']
        for item in self.map_canvas.find_withtag(f'd_{ip}'):
            self.map_canvas.move(item, dx, dy)
        self._map_drag['x'] = e.x
        self._map_drag['y'] = e.y
        if ip in self.scanner.devices:
            self.scanner.devices[ip].x = e.x
            self.scanner.devices[ip].y = e.y
        self._redraw_links()

    def _map_release(self, e):
        self._map_drag = {'ip': None, 'x': 0, 'y': 0}

    def _map_dblclick(self, e):
        ip = self._find_dev(e.x, e.y)
        if ip:
            self.selected_ip = ip
            self._show_details(ip)
            self.con_ip_var.set(ip)
            self.port_ip_var.set(ip)

    def _redraw_links(self):
        self.map_canvas.delete('link')
        gw = self.scanner.gateway_ip
        if gw not in self.scanner.devices: return
        gd = self.scanner.devices[gw]
        for ip, d in self.scanner.devices.items():
            if ip == gw: continue
            lc = C['link_on'] if d.status == 'online' else C['link_off']
            self.map_canvas.create_line(gd.x, gd.y, d.x, d.y,
                                        fill=lc, width=2, dash=(8,4), tags='link')
        self.map_canvas.tag_raise('dev')
        self.map_canvas.tag_raise('lbl')

    
    def _show_details(self, ip: str):
        dev = self.scanner.devices.get(ip)
        if not dev: return
        for w in self.detail_scroll.winfo_children():
            w.destroy()

        #icon
        tf = ctk.CTkFrame(self.detail_scroll, fg_color=C['card'], corner_radius=8)
        tf.pack(fill='x', padx=4, pady=4)
        try:
            img = self.icons.get(dev.device_type, 48, dev.status)
            tki = ImageTk.PhotoImage(img)
            self.tk_imgs[f'det_{ip}'] = tki
            ctk.CTkLabel(tf, image=tki, text='').pack(pady=(10,0))
        except Exception:
            pass
        lbl = DEVICE_LABELS.get(dev.device_type, dev.device_type)
        st  = '' if dev.status == 'online' else 'OFFLINE'
        sc  = C['green'] if dev.status == 'online' else C['red']
        ctk.CTkLabel(tf, text=lbl.upper(), font=F['sec'], text_color=C['teal']).pack(padx=10, pady=(5,0))
        ctk.CTkLabel(tf, text=st, font=F['small'], text_color=sc).pack(padx=10, pady=(0,8))

        # Sections
        sections = [
            ('Network', [('IP', dev.ip), ('MAC', dev.mac),
                             ('Host', dev.hostname), ('Vendor', dev.vendor),
                             ('Gateway', 'Yes ✓' if dev.is_gateway else 'No')]),
            ('System',  [('OS', dev.os_guess), ('TTL', str(dev.ttl)),
                             ('Latency', f'{dev.latency:.1f} ms')]),
        ]
        if dev.open_ports:
            pl = [('', f'  {p}/tcp → {dev.services.get(p,"?")}') for p in dev.open_ports]
            sections.append(('Ports', pl))

        for title, items in sections:
            sf = ctk.CTkFrame(self.detail_scroll, fg_color=C['card'], corner_radius=8)
            sf.pack(fill='x', padx=4, pady=2)
            ctk.CTkLabel(sf, text=title, font=F['sec'],
                         text_color=C['teal']).pack(padx=8, pady=(6,3), anchor='w')
            for lbl_t, val in items:
                row = ctk.CTkFrame(sf, fg_color='transparent')
                row.pack(fill='x', padx=8, pady=1)
                if lbl_t:
                    ctk.CTkLabel(row, text=f'{lbl_t}:', font=F['tiny'],
                                 text_color=C['text4'], width=75,
                                 anchor='w').pack(side='left')
                ctk.CTkLabel(row, text=str(val), font=F['tiny'],
                             text_color=C['text2'], anchor='w').pack(side='left', fill='x', expand=True)
            ctk.CTkFrame(sf, fg_color='transparent', height=4).pack()

        # Actions
        af = ctk.CTkFrame(self.detail_scroll, fg_color=C['card'], corner_radius=8)
        af.pack(fill='x', padx=4, pady=4)
        ctk.CTkLabel(af, text='⚡ Actions', font=F['sec'],
                     text_color=C['teal']).pack(padx=8, pady=(6,3), anchor='w')
        actions = []
        if any(p in dev.open_ports for p in (80, 8080)):
            actions.append(('Web Interface',
                            lambda i=ip: __import__('webbrowser').open(f'http://{i}')))
        if 443 in dev.open_ports:
            actions.append(('HTTPS',
                            lambda i=ip: __import__('webbrowser').open(f'https://{i}')))
        if 22 in dev.open_ports:
            actions.append(('SSH',
                            lambda i=ip: [self.con_ip_var.set(i),
                                          self.tabs.set('Console')]))
        if 3389 in dev.open_ports:
            actions.append(('RDP',
                            lambda i=ip: subprocess.Popen(f'mstsc /v:{i}', shell=True)))
        actions += [
            ('Port Scan', lambda i=ip: [self.port_ip_var.set(i),
                                            self.tabs.set('Ports'),
                                            self._port_scan()]),
            ('Sniff',     lambda i=ip: self._sniff_dev(i)),
            ('Ping',      lambda i=ip: [self.tabs.set('🏓 Ping'),
                                            self.cmd_var.set(f'ping {i}'),
                                            self._run_cmd(None)]),
            ('Reboot',    lambda i=ip: self._power_dialog(i, 'reboot')),
            ('Shutdown',   lambda i=ip: self._power_dialog(i, 'shutdown')),
            ('Wake-on-LAN', lambda i=ip: self._power_dialog(i, 'wol')),
        ]
        for text, cmd in actions:
            ctk.CTkButton(af, text=text, font=F['mono_s'],
                          fg_color=C['bg2'], hover_color=C['hover'],
                          border_width=1, border_color=C['border'],
                          height=28, command=cmd).pack(fill='x', padx=8, pady=2)
        ctk.CTkFrame(af, fg_color='transparent', height=8).pack()

#power dialog
    def _power_dialog(self, ip: str, action: str):
        dev = self.scanner.devices.get(ip)
        if not dev:
            return

        dlg = ctk.CTkToplevel(self)
        dlg.title(f'Power Control — {ip}')
        dlg.geometry('460x480')
        dlg.transient(self)
        dlg.grab_set()
        dlg.configure(fg_color=C['bg'])

        titles = {
            'reboot':   ('Reboot',       C['orange']),
            'shutdown': ('Shutdown',      C['red']),
            'wol':      ('Wake-on-LAN',  C['green']),
        }
        t_text, t_clr = titles.get(action, ('Power', C['blue']))
        dos = self.power.detect_os(dev)

        # Header
        hdr = ctk.CTkFrame(dlg, fg_color=C['panel'], height=50, corner_radius=0)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=f'  {t_text}',
                     font=F['panel'], text_color=t_clr).pack(side='left', padx=10, pady=10)
        ctk.CTkLabel(hdr, text=ip,
                     font=F['mono_s'], text_color=C['text3']).pack(side='right', padx=10)

        body = ctk.CTkScrollableFrame(dlg, fg_color=C['bg'])
        body.pack(fill='both', expand=True, padx=10, pady=10)

        # Device info
        info_f = ctk.CTkFrame(body, fg_color=C['card'], corner_radius=8)
        info_f.pack(fill='x', pady=5)
        ctk.CTkLabel(info_f, text='Info',
                     font=F['sec'], text_color=C['teal']).pack(padx=10, pady=(8,4), anchor='w')
        for lbl, val in (('IP', dev.ip), ('Vendor', dev.vendor),
                          ('OS', dev.os_guess), ('Detected OS', dos.value),
                          ('MAC', dev.mac)):
            row = ctk.CTkFrame(info_f, fg_color='transparent')
            row.pack(fill='x', padx=10, pady=1)
            ctk.CTkLabel(row, text=f'{lbl}:', font=F['tiny'],
                         text_color=C['text4'], width=90, anchor='w').pack(side='left')
            ctk.CTkLabel(row, text=str(val), font=F['tiny'],
                         text_color=C['text2'], anchor='w').pack(side='left')
        ctk.CTkFrame(info_f, fg_color='transparent', height=5).pack()

        # Credentials (optional)
        cred_f = ctk.CTkFrame(body, fg_color=C['card'], corner_radius=8)
        cred_f.pack(fill='x', pady=5)
        ctk.CTkLabel(cred_f, text='Credentials (optional)',
                     font=F['sec'], text_color=C['teal']).pack(padx=10, pady=(8,4), anchor='w')
        ctk.CTkLabel(cred_f,
                     text='Leave blank for auto-mode\n'
                          '(tries HTTP API, default passwords, SSH keys...)',
                     font=F['tiny'], text_color=C['text4'],
                     justify='left').pack(padx=10, anchor='w')

        user_var   = tk.StringVar(value=self.con_user_var.get())
        pass_var   = tk.StringVar(value=self.con_pass_var.get())
        enable_var = tk.StringVar()

        for lbl, var, show in (('Username:', user_var, ''),
                                ('Password:', pass_var, '*'),
                                ('Enable (Cisco):', enable_var, '*')):
            row = ctk.CTkFrame(cred_f, fg_color='transparent')
            row.pack(fill='x', padx=10, pady=3)
            ctk.CTkLabel(row, text=lbl, font=F['small'],
                         text_color=C['text4'], width=110, anchor='w').pack(side='left')
            ctk.CTkEntry(row, textvariable=var, font=F['mono_s'],
                         fg_color=C['input'], height=26,
                         show=show).pack(side='left', fill='x', expand=True, padx=5)
        ctk.CTkFrame(cred_f, fg_color='transparent', height=5).pack()

        # Auto-mode info
        auto_f = ctk.CTkFrame(body, fg_color=C['card'], corner_radius=8)
        auto_f.pack(fill='x', pady=5)
        ctk.CTkLabel(auto_f, text='Auto-Mode (no credentials)',
                     font=F['sec'], text_color=C['teal']).pack(padx=10, pady=(8,4), anchor='w')
        methods_text = (
            '1. HTTP API   — router web panel (no auth)\n'
            '2. SSH Keys   — system SSH keys / agent\n'
            '3. Defaults   — common default passwords\n'
            '4. SNMP       — enterprise switches\n'
            '5. UPnP       — home routers\n'
            '6. NetBIOS    — Windows LAN (no-auth)'
        )
        ctk.CTkLabel(auto_f, text=methods_text,
                     font=F['tiny'], text_color=C['text3'],
                     justify='left').pack(padx=15, pady=(0,8), anchor='w')

        # Warning
        warn_f = ctk.CTkFrame(body, fg_color='#1A0000', corner_radius=8)
        warn_f.pack(fill='x', pady=5)
        warn_txt = {
            'reboot':   'Device will restart. Connections will drop.',
            'shutdown': 'Device will POWER OFF. Needs physical access to turn on.',
            'wol':      'Magic packet sent. Device must support Wake-on-LAN.',
        }
        ctk.CTkLabel(warn_f, text=warn_txt.get(action, 'Proceed with caution'),
                     font=F['small'], text_color=C['orange'],
                     wraplength=380).pack(padx=10, pady=8)

        # Buttons
        bf = ctk.CTkFrame(dlg, height=50, fg_color=C['panel'], corner_radius=0)
        bf.pack(fill='x', side='bottom')
        bf.pack_propagate(False)

        def _exec():
            dlg.destroy()
            self.tabs.set('Console')
            self._cprint(f'\n{"═"*48}\n'
                         f'  {t_text.upper()} → {ip}\n'
                         f'  Mode: {"credentials" if user_var.get() else "auto (no password)"}\n'
                         f'{"═"*48}\n\n', 'info')

            def _out(msg):
                self.after(0, lambda: self._cprint(msg))

            def _go():
                pa = {
                    'reboot':   PowerAction.REBOOT,
                    'shutdown': PowerAction.SHUTDOWN,
                    'wol':      PowerAction.WOL,
                }.get(action, PowerAction.REBOOT)

                result = self.power.execute(
                    action=pa,
                    ip=ip,
                    username=user_var.get(),
                    password=pass_var.get(),
                    device=dev,
                    enable_pw=enable_var.get(),
                    cb=_out,
                )

                status_msg = (
                    f'\n[{"+" if result.success else "!"}] '
                    f'{"SUCCESS" if result.success else "FAILED"}: '
                    f'{result.message}\n'
                    f'  Method: {result.method}\n\n'
                )
                self.after(0, lambda: self._cprint(
                    status_msg,
                    'prompt' if result.success else 'err'
                ))

                # Update device status in UI
                if result.success and action == 'shutdown':
                    time.sleep(5)
                    if ip in self.scanner.devices:
                        self.scanner.devices[ip].status = 'offline'
                    self.after(0, self._draw_map)
                elif result.success and action == 'reboot':
                    time.sleep(3)
                    if ip in self.scanner.devices:
                        self.scanner.devices[ip].status = 'offline'
                    self.after(0, self._draw_map)
                    # Check if it came back
                    self.after(30000, lambda: self._check_back_online(ip))

            threading.Thread(target=_go, daemon=True).start()

        # Quick execute without creds button
        ctk.CTkButton(bf, text='Auto (no password)',
                      font=F['bold'], fg_color=C['purple'],
                      hover_color=C['hover'],
                      width=160, height=32,
                      command=lambda: [user_var.set(''), pass_var.set(''), _exec()]
                      ).pack(side='left', padx=10, pady=9)

        ctk.CTkButton(bf, text='Cancel', font=F['body'],
                      fg_color=C['bg2'], width=90, height=32,
                      command=dlg.destroy).pack(side='right', padx=10, pady=9)

        ctk.CTkButton(bf, text='Execute', font=F['bold'],
                      fg_color=t_clr, width=120, height=32,
                      command=_exec).pack(side='right', padx=5, pady=9)

    def _check_back_online(self, ip: str):
        """Check if rebooted device came back"""
        if self.power.check_alive(ip):
            if ip in self.scanner.devices:
                self.scanner.devices[ip].status = 'online'
            self._cprint(f'+ ✅ {ip} is back online!\n', 'prompt')
            self.after(0, self._draw_map)
        else:
            self._cprint(f'+ {ip} still offline...\n')
            #30s
            self.after(30000, lambda: self._check_back_online(ip))
        def _exec():
            dlg.destroy()
            self.tabs.set('Console')
            def _out(m): self.after(0, lambda: self._cprint(m))
            def _go():
                pa = {'reboot': PowerAction.REBOOT,
                      'shutdown': PowerAction.SHUTDOWN,
                      'wol': PowerAction.WOL}.get(action, PowerAction.REBOOT)
                self.power.execute(pa, ip, user_var.get(), pass_var.get(),
                                   dev, enable_var.get(), _out)
            threading.Thread(target=_go, daemon=True).start()

        bf = ctk.CTkFrame(dlg, height=45, fg_color=C['panel'])
        bf.pack(fill='x', side='bottom')
        bf.pack_propagate(False)
        ctk.CTkButton(bf, text='Cancel', font=F['body'],
                      fg_color=C['bg2'], width=90, height=30,
                      command=dlg.destroy).pack(side='right', padx=10, pady=7)
        ctk.CTkButton(bf, text='✓ Execute', font=F['bold'],
                      fg_color=t_clr, width=130, height=30,
                      command=_exec).pack(side='right', padx=5, pady=7)

   #traffic
    def _toggle_sniff(self):
        if self.sniffer.is_sniffing:
            self.sniffer.stop()
            self.sniff_lbl.configure(text='Stopped', text_color=C['red'])
            self._set_status('Stopped')
            return
        bpf = self.bpf_var.get() or None
        def _on(p): self.after(0, lambda pp=p: self._add_pkt(pp))
        ok = self.sniffer.start(bpf=bpf, pkt_cb=_on)
        if ok:
            self.sniff_lbl.configure(text='CAPTURING', text_color=C['green'])
            self._set_status('Capturing...', C['green'])
            self.tabs.set('Traffic')
            self._update_pkt_stats()
        else:
            self.sniff_lbl.configure(text='Failed (need root?)', text_color=C['red'])

    def _add_pkt(self, p):
        tag = p.protocol if p.protocol in PROTO_COLORS else 'default'
        self.pkt_tree.insert('', 'end',
                              values=(p.timestamp,
                                      p.src_ip or p.src_mac,
                                      p.dst_ip or p.dst_mac,
                                      p.protocol, p.length,
                                      p.info[:80]),
                              tags=(tag,))
        ch = self.pkt_tree.get_children()
        if ch: self.pkt_tree.see(ch[-1])
        if len(ch) > 5000: self.pkt_tree.delete(ch[0])

    def _update_pkt_stats(self):
        if not self.sniffer.is_sniffing: return
        s  = self.sniffer.stats
        tb = s['total_bytes']
        bs = (f'{tb/1e6:.1f}MB' if tb > 1e6 else
              f'{tb/1e3:.1f}KB' if tb > 1e3 else f'{tb}B')
        self.pkt_stats_lbl.configure(
            text=f"{s['total_packets']} pkts | {bs} | {s['packets_per_second']} p/s")
        self.after(1000, self._update_pkt_stats)

    def _sniff_dev(self, ip: str):
        self.bpf_var.set(f'host {ip}')
        self.sniffer.clear()
        self.pkt_tree.delete(*self.pkt_tree.get_children())
        if self.sniffer.is_sniffing:
            self.sniffer.stop()
            time.sleep(0.3)
        self._toggle_sniff()

    #console
    def _cprint(self, text: str, tag: str = None):
        self.console.insert('end', text, tag)
        self.console.see('end')

    def _ssh_connect(self):
        ip = self.con_ip_var.get().strip()
        u  = self.con_user_var.get().strip()
        pw = self.con_pass_var.get()
        if not ip:
            self._cprint('[!] Enter target IP\n', 'err')
            return
        self._cprint(f'[*] SSH → {ip} as {u}...\n', 'info')
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            def _go():
                try:
                    client.connect(ip, username=u, password=pw, timeout=10)
                    self._ssh_client = client
                    self.after(0, lambda: self._cprint(f'[+] Connected to {ip}\n', 'prompt'))
                except Exception as e:
                    self.after(0, lambda: self._cprint(f'[!] {e}\n', 'err'))
            threading.Thread(target=_go, daemon=True).start()
        except ImportError:
            self._cprint('[!] paramiko not installed\n', 'err')

    def _ssh_disconnect(self):
        try:
            if self._ssh_client:
                self._ssh_client.close()
                self._ssh_client = None
                self._cprint('+ Disconnected\n', 'prompt')
        except Exception:
            pass

    def _run_cmd(self, _=None):
        cmd = self.cmd_var.get().strip()
        if not cmd: return
        self.cmd_var.set('')
        self._cprint(f'$ {cmd}\n', 'prompt')

        if cmd == 'help':
            self._cprint(
                '\n── Commands ─────────────────────────\n'
                '  help              This help\n'
                '  clear             Clear console\n'
                '  devices           List devices\n'
                '  ping <ip>         Ping host\n'
                '  traceroute <ip>   Traceroute\n'
                '  scan <ip>         Port scan\n'
                '  reboot <ip>       Reboot device\n'
                '  shutdown <ip>     Shutdown device\n'
                '  wol <ip>          Wake-on-LAN\n'
                '  power-history     Power log\n'
                '  bt-scan           Bluetooth scan\n'
                '  wifi-scan         WiFi scan\n'
                '\nWhen SSH connected → sent to remote host\n\n')
            return

        if cmd == 'clear':
            self.console.delete('1.0', 'end')
            return

        if cmd == 'devices':
            for ip, d in self.scanner.devices.items():
                self._cprint(f'  {ip:16s}  {d.hostname:22s}  [{d.device_type}]\n')
            return

        if cmd.startswith('ping '):
            target = cmd.split()[1]
            def _ping():
                ok, lat, ttl = self.scanner.ping_host(target)
                state = 'Alive' if ok else 'Dead'
                self.after(0, lambda: self._cprint(
                    f'  {target}: {state}  {lat:.1f}ms  TTL={ttl}\n'))
            threading.Thread(target=_ping, daemon=True).start()
            return

        if cmd.startswith('traceroute ') or cmd.startswith('tracert '):
            target = cmd.split()[1]
            def _trace():
                c = (f'tracert -d -w 1000 {target}'
                     if platform.system() == 'Windows'
                     else f'traceroute -n -w 1 {target}')
                proc = subprocess.Popen(c, shell=True,
                                        stdout=subprocess.PIPE, text=True)
                for line in iter(proc.stdout.readline, ''):
                    self.after(0, lambda l=line: self._cprint(l))
                proc.wait(timeout=30)
            threading.Thread(target=_trace, daemon=True).start()
            return

        if cmd.startswith('scan '):
            target = cmd.split()[1]
            self.port_ip_var.set(target)
            self.tabs.set('Ports')
            self._port_scan()
            return

        for pwr_cmd, pwr_action in (('reboot', 'reboot'),
                                     ('shutdown', 'shutdown'),
                                     ('wol', 'wol')):
            if cmd.startswith(f'{pwr_cmd} '):
                ip = cmd.split()[1]
                if ip in self.scanner.devices:
                    self._power_dialog(ip, pwr_action)
                else:
                    self._cprint(f'[!] {ip} not found in scan results\n', 'err')
                return

        if cmd == 'power-history':
            h = self.power.history
            if not h:
                self._cprint('[*] No power actions recorded\n')
                return
            for r in h[-20:]:
                icon = '✅' if r.success else '❌'
                self._cprint(f'  {icon}  {r.action:12s}  {r.ip:16s}  '
                             f'{r.method:10s}  {r.message}\n')
            return

        if cmd == 'bt-scan':
            self.tabs.set('Bluetooth')
            self._bt_full()
            return

        if cmd == 'wifi-scan':
            self.tabs.set('WiFi')
            self._wifi_scan()
            return

        #ssh
        if self._ssh_client:
            def _exec():
                try:
                    _, stdout, stderr = self._ssh_client.exec_command(cmd, timeout=30)
                    out = stdout.read().decode('utf-8', errors='ignore')
                    err = stderr.read().decode('utf-8', errors='ignore')
                    result = out + (f'\n[STDERR] {err}' if err.strip() else '')
                    self.after(0, lambda: self._cprint(result + '\n'))
                except Exception as e:
                    self.after(0, lambda: self._cprint(f'[!] {e}\n', 'err'))
            threading.Thread(target=_exec, daemon=True).start()
        else:
            self._cprint('[!] No SSH session. Use SSH Connect button.\n', 'err')

#port scaner
    def _port_scan(self):
        target = self.port_ip_var.get().strip()
        if not target: return
        rng = self.port_range_var.get().strip()
        self.port_out.delete('1.0', 'end')
        self.port_out.insert('end', f"{'═'*50}\n  TARGET: {target}   PORTS: {rng}\n{'═'*50}\n\n", 'hdr')

        ports = []
        try:
            for part in rng.split(','):
                part = part.strip()
                if '-' in part:
                    a, b = part.split('-')
                    ports.extend(range(int(a), int(b)+1))
                else:
                    ports.append(int(part))
        except ValueError:
            self.port_out.insert('end', '+ Invalid port format\n')
            return

        self._set_status(f'Scanning {len(ports)} ports on {target}...', C['blue'])

        def _go():
            t0  = time.time()
            res = self.scanner.scan_ports(target, ports)
            el  = time.time() - t0
            self.after(0, lambda: self._show_ports(target, res, ports, el))

        threading.Thread(target=_go, daemon=True).start()

    def _show_ports(self, target: str, res: dict, all_ports: list, elapsed: float):
        self.port_out.insert('end', f"  {'PORT':>7s}  {'STATE':>7s}  SERVICE\n", 'hdr')
        self.port_out.insert('end', f"  {'─'*40}\n", 'dim')
        for port in sorted(res):
            self.port_out.insert('end', f'  {port:>7d}  {"OPEN":>7s}  {res[port]}\n', 'open')
        self.port_out.insert('end',
            f'\n  {len(res)} open / {len(all_ports)} scanned ({elapsed:.1f}s)\n', 'dim')
        self._set_status(f'✅ {len(res)} open ports on {target}', C['green'])

    
    def _bt_write(self, text: str, tag: str = None):
        self.bt_out.insert('end', text, tag)
        self.bt_out.see('end')

    def _bt_update_tree(self):
        self.bt_tree.delete(*self.bt_tree.get_children())
        for addr, d in sorted(self.bt.devices.items(),
                               key=lambda kv: kv[1].rssi, reverse=True):
            dist = d.est_distance()
            ds   = f'~{dist}m' if dist > 0 else '?'
            sq   = d.signal_quality().lower().replace(' ', '_')
            self.bt_tree.insert('', 'end',
                                 values=(addr, d.name[:18], f'{d.rssi}dBm',
                                         d.device_type, ds, d.manufacturer[:14]),
                                 tags=(sq,))
        self.bt_count_lbl.configure(text=f'{len(self.bt.devices)} devices')

    def _bt_ble(self):
        self.bt_out.delete('1.0', 'end')
        self._bt_write('[*] BLE scan (15s)...\n', 'info')
        self.bt.on_complete = lambda n: self.after(0, lambda: [
            self._bt_write(f'\n[+] Done — {n} devices\n', 'info'),
            self._bt_update_tree()])

        def _on_found(dev):
            dist = dev.est_distance()
            ds   = f'~{dist}m' if dist > 0 else '?'
            self.after(0, lambda: [
                self._bt_write(f'  [BLE] {dev.address}  "{dev.name}"  '
                               f'{dev.rssi}dBm  {ds}  [{dev.device_type}]\n', 'found'),
                self._bt_update_tree()])

        self.bt.start_ble_scan(15, cb=_on_found)

    def _bt_classic(self):
        self.bt_out.delete('1.0', 'end')
        self._bt_write('[*] Classic BT scan...\n', 'info')
        self.bt.scan_classic(10, cb=lambda m: self.after(0, lambda: [
            self._bt_write(m), self._bt_update_tree()]))

    def _bt_full(self):
        self.bt_out.delete('1.0', 'end')
        self.bt.full_scan(callback=lambda m: self.after(0, lambda: [
            self._bt_write(m), self._bt_update_tree()]))

    def _bt_monitor(self):
        self.bt_out.delete('1.0', 'end')
        self.bt.start_monitor(cb=lambda m: self.after(0, lambda: [
            self._bt_write(m), self._bt_update_tree()]))

    def _bt_connect(self, _=None):
        sel = self.bt_tree.selection()
        if not sel: return
        addr = self.bt_tree.item(sel[0], 'values')[0]
        if messagebox.askyesno('BLE Connect',
                               f'Connect to {addr}\nand read GATT services?'):
            self._bt_write(f'\n[*] Connecting to {addr}...\n', 'info')
            self.bt.connect_device(addr,
                                    cb=lambda m: self.after(0, lambda: self._bt_write(m)))

    #wifi
    def _wifi_write(self, text: str, tag: str = None):
        self.wifi_out.insert('end', text, tag)
        self.wifi_out.see('end')

    def _wifi_update_tree(self):
        self.wifi_tree.delete(*self.wifi_tree.get_children())
        for net in sorted(self.wifi.networks.values(),
                          key=lambda n: n.signal_dbm, reverse=True):
            if   net.is_connected:          tag = 'connected'
            elif 'Open'  in net.security:   tag = 'open'
            elif 'WEP'   in net.security:   tag = 'wep'
            elif 'WPA3'  in net.security:   tag = 'wpa3'
            elif 'WPA2'  in net.security:   tag = 'wpa2'
            elif 'WPA'   in net.security:   tag = 'wpa'
            else:                           tag = ''
            mark = '◀ ' if net.is_connected else ''
            self.wifi_tree.insert('', 'end',
                                   values=(f'{mark}{net.ssid}', net.bssid,
                                           net.channel,
                                           f'{net.bars()} {net.signal_dbm}dBm',
                                           net.security, net.band,
                                           net.vendor[:12]),
                                   tags=(tag,))
        self.wifi_count_lbl.configure(text=f'{len(self.wifi.networks)} networks')

    def _wifi_scan(self):
        self.wifi_out.delete('1.0', 'end')
        self.wifi.scan(cb=lambda m: self.after(0, lambda: [
            self._wifi_write(m), self._wifi_update_tree()]))

    def _save(self):
        fn = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('PCAP', '*.pcap'), ('Text', '*.txt')])
        if not fn: return
        try:
            if fn.endswith('.json'):
                data = {'network': self.net_info,
                        'devices': {ip: d.to_dict()
                                    for ip, d in self.scanner.devices.items()}}
                with open(fn, 'w') as f:
                    json.dump(data, f, indent=2)
            elif fn.endswith('.pcap'):
                self.sniffer.save_pcap(fn)
            else:
                with open(fn, 'w') as f:
                    f.write('NetMap Pro Scan Results\n' + '='*50 + '\n')
                    for ip, d in self.scanner.devices.items():
                        f.write(f'\n{ip}\n')
                        for k, v in d.to_dict().items():
                            f.write(f'  {k}: {v}\n')
            self._set_status(f'Saved: {fn}', C['green'])
        except Exception as e:
            messagebox.showerror('Error', str(e))

    def _clear_all(self):
        if not messagebox.askyesno('Confirm', 'Clear all data?'): return
        self.scanner.devices.clear()
        self.sniffer.clear()
        self.bt.clear()
        self.wifi.clear()
        for tree in (self.dev_tree, self.pkt_tree, self.bt_tree, self.wifi_tree):
            tree.delete(*tree.get_children())
        for widget in (self.console, self.port_out, self.bt_out, self.wifi_out):
            widget.delete('1.0', 'end')
        self._details_placeholder()
        self.map_canvas.delete('all')
        self._draw_grid()
        self.dev_count.configure(text='(0)')
        self.progress.set(0)
        self._set_status('Cleared')

    def _on_close(self):
        self.scanner.stop_scan()
        self.sniffer.stop()
        self.bt.stop()
        self.wifi.stop()
        try:
            if self._ssh_client:
                self._ssh_client.close()
        except Exception:
            pass
        self.destroy()