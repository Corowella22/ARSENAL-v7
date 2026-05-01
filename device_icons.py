from PIL import Image, ImageDraw, ImageFont, ImageFilter
from typing import Dict

class IconRenderer:
    COL = {
        'router':     ('#1B67B2', '#0D4F8B', '#3A8FE0'),
        'switch':     ('#2E86C1', '#1A5276', '#5DADE2'),
        'computer':   ('#5B5B5B', '#3D3D3D', '#1C2833'),
        'server':     ('#2C3E50', '#34495E', '#1A252F'),
        'phone':      ('#2C2C2C', '#1A1A2E', '#0D1B2A'),
        'wireless_ap':('#455A64', '#263238', '#78909C'),
        'iot':        ('#00695C', '#004D40', '#4DB6AC'),
        'unknown':    ('#616161', '#424242', '#9E9E9E'),
    }

    def __init__(self, size: int = 64):
        self.size  = size
        self.cache: Dict[str, Image.Image] = {}
        try:
            self._font = ImageFont.truetype('arial.ttf', 10)
        except Exception:
            self._font = ImageFont.load_default()

    def _canvas(self, s: int):
        img  = Image.new('RGBA', (s, s), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        return img, draw

    def _led(self, draw: ImageDraw.Draw, x: int, y: int, status: str, r: int = 4):
        clr = '#2ECC71' if status == 'online' else '#E74C3C'
        draw.ellipse([x-r, y-r, x+r, y+r], fill=clr, outline='white', width=1)

    def _shadow(self, img: Image.Image) -> Image.Image:
        sh = Image.new('RGBA', img.size, (0, 0, 0, 0))
        for x in range(img.width):
            for y in range(img.height):
                if img.getpixel((x, y))[3] > 50:
                    sx, sy = x + 2, y + 2
                    if sx < img.width and sy < img.height:
                        sh.putpixel((sx, sy), (0, 0, 0, 40))
        sh  = sh.filter(ImageFilter.GaussianBlur(1.5))
        return Image.alpha_composite(sh, img)

    def get(self, dtype: str, size: int = None, status: str = 'online') -> Image.Image:
        sz  = size or self.size
        key = f'{dtype}_{sz}_{status}'
        if key in self.cache:
            return self.cache[key]
        fn  = {
            'router': self._router, 'gateway': self._router,
            'switch': self._switch, 'computer': self._pc,
            'laptop': self._pc,     'server': self._server,
            'phone': self._phone,   'wireless_ap': self._ap,
            'iot': self._iot,
        }.get(dtype, self._unknown)
        img = fn(sz, status)
        self.cache[key] = img
        return img

    def _router(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        c = self.COL['router']
        bl, br = int(s*.10), int(s*.90)
        bt, bb = int(s*.25), int(s*.70)
        eh = int(s*.12)
        d.rectangle([bl, bt+eh//2, br, bb-eh//2], fill=c[0])
        d.ellipse([bl, bt, br, bt+eh], fill=c[2], outline=c[1], width=1)
        d.ellipse([bl, bb-eh, br, bb], fill=c[1])
        ay = int(s*.44)
        pts = [(int(s*.25), ay-int(s*.05)), (int(s*.50), ay-int(s*.05)),
               (int(s*.50), ay-int(s*.09)), (int(s*.65), ay),
               (int(s*.50), ay+int(s*.09)), (int(s*.50), ay+int(s*.05)),
               (int(s*.25), ay+int(s*.05))]
        d.polygon(pts, fill='white')
        ay2 = int(s*.58)
        pts2 = [(int(s*.75), ay2-int(s*.05)), (int(s*.50), ay2-int(s*.05)),
                (int(s*.50), ay2-int(s*.09)), (int(s*.35), ay2),
                (int(s*.50), ay2+int(s*.09)), (int(s*.50), ay2+int(s*.05)),
                (int(s*.75), ay2+int(s*.05))]
        d.polygon(pts2, fill='white')
        py = int(s*.72)
        for i in range(4):
            px = int(s*.25) + i * int(s*.14)
            d.rectangle([px, py, px+int(s*.06), py+int(s*.04)], fill='#F4D03F', outline='#000')
        self._led(d, int(s*.85), int(s*.18), status)
        return self._shadow(img)

    def _switch(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        c = self.COL['switch']
        d.rounded_rectangle([int(s*.05), int(s*.30), int(s*.95), int(s*.70)],
                            radius=int(s*.04), fill=c[0], outline=c[1], width=2)
        cx, cy = int(s*.35), int(s*.50)
        ar = int(s*.10)
        for dx in (-1, 1):
            d.line([(cx, cy), (cx+dx*ar, cy)], fill='white', width=2)
            d.polygon([(cx+dx*ar, cy-int(s*.04)),
                        (cx+dx*(ar+int(s*.05)), cy),
                        (cx+dx*ar, cy+int(s*.04))], fill='white')
        for dy in (-1, 1):
            d.line([(cx, cy), (cx, cy+dy*ar)], fill='white', width=2)
            d.polygon([(cx-int(s*.04), cy+dy*ar),
                        (cx, cy+dy*(ar+int(s*.05))),
                        (cx+int(s*.04), cy+dy*ar)], fill='white')
        for row in range(2):
            for i in range(4):
                px = int(s*.50) + i*int(s*.07)
                py = int(s*.42) + row*(int(s*.06)+int(s*.03))
                d.rectangle([px, py, px+int(s*.05), py+int(s*.06)],
                            fill='#F4D03F', outline='#000')
        self._led(d, int(s*.88), int(s*.22), status)
        return self._shadow(img)

    def _pc(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        ml, mr, mt, mb = int(s*.15), int(s*.85), int(s*.08), int(s*.58)
        d.rounded_rectangle([ml, mt, mr, mb], radius=int(s*.03),
                            fill='#3D3D3D', outline='#2C2C2C', width=2)
        m = int(s*.04)
        scr = [ml+m, mt+m, mr-m, mb-m-int(s*.03)]
        d.rectangle(scr, fill='#1C2833')
        if status == 'online':
            ws = int(s*.06)
            cx = (scr[0]+scr[2])//2
            cy = (scr[1]+scr[3])//2
            for (ox, oy), wc in zip([(-1,-1),(1,-1),(-1,1),(1,1)],
                                     ['#F25022','#7FBA00','#00A4EF','#FFB900']):
                gap = 2
                x1, y1 = cx+ox*gap, cy+oy*gap
                x2, y2 = cx+ox*(gap+ws), cy+oy*(gap+ws)
                d.rectangle([min(x1,x2), min(y1,y2), max(x1,x2), max(y1,y2)], fill=wc)
        sw = int(s*.08)
        d.rectangle([s//2-sw//2, mb, s//2+sw//2, mb+int(s*.08)], fill='#7B7B7B')
        bw = int(s*.30)
        d.rounded_rectangle([s//2-bw//2, mb+int(s*.08), s//2+bw//2, mb+int(s*.11)],
                            radius=2, fill='#7B7B7B')
        self._led(d, int(s*.88), int(s*.12), status)
        return self._shadow(img)

    def _server(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        rl, rr, rt, rb = int(s*.15), int(s*.85), int(s*.05), int(s*.88)
        d.rounded_rectangle([rl, rt, rr, rb], radius=int(s*.03),
                            fill='#2C3E50', outline='#1A1A2E', width=2)
        uh = int(s*.15); ug = int(s*.03); um = int(s*.04)
        for i in range(4):
            uy = rt+um + i*(uh+ug)
            if uy+uh > rb-um: break
            d.rounded_rectangle([rl+um, uy, rr-um, uy+uh], radius=2, fill='#34495E', outline='#2C3E50')
            lx = rr-um-int(s*.10)
            for li, lc in enumerate(['#2ECC71','#2ECC71','#F39C12']):
                if status == 'offline': lc = '#333333'
                d.ellipse([lx+li*6, uy+3, lx+li*6+4, uy+7], fill=lc)
        self._led(d, int(s*.82), int(s*.08), status, 5)
        return self._shadow(img)

    def _phone(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        pl, pr, pt, pb = int(s*.28), int(s*.72), int(s*.08), int(s*.88)
        d.rounded_rectangle([pl, pt, pr, pb], radius=int(s*.06),
                            fill='#2C2C2C', outline='#1A1A1A', width=2)
        sm = int(s*.04)
        scr = [pl+sm, pt+int(s*.08), pr-sm, pb-int(s*.08)]
        d.rounded_rectangle(scr, radius=int(s*.02), fill='#0D1B2A')
        if status == 'online':
            cols = ['#4CAF50','#2196F3','#FF9800','#E91E63',
                    '#9C27B0','#00BCD4','#FF5722','#3F51B5']
            isz = int(s*.06); ig = int(s*.02)
            for ai, ac in enumerate(cols):
                row  = ai // 3
                col  = ai % 3
                ax   = scr[0]+int(s*.03)+col*(isz+ig)
                ay   = scr[1]+int(s*.06)+row*(isz+ig)
                if ay+isz < scr[3]-int(s*.05):
                    d.rounded_rectangle([ax, ay, ax+isz, ay+isz], radius=2, fill=ac)
        d.ellipse([s//2-3, pt+int(s*.03), s//2+3, pt+int(s*.07)], fill='#333333')
        self._led(d, int(s*.72), int(s*.08), status)
        return self._shadow(img)

    def _ap(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        cx, cy = s//2, int(s*.55)
        rx, ry = int(s*.35), int(s*.12)
        d.ellipse([cx-rx, cy-ry, cx+rx, cy+ry+int(s*.05)], fill='#546E7A')
        d.ellipse([cx-rx, cy-ry, cx+rx, cy+ry], fill='#ECEFF1', outline='#90A4AE', width=1)
        led = '#4CAF50' if status == 'online' else '#F44336'
        d.ellipse([cx-3, cy-2, cx+3, cy+2], fill=led)
        if status == 'online':
            for i in range(3):
                ar = int(s*(0.12+i*0.10))
                dy = int(s*.15)
                d.arc([cx-ar, dy-ar, cx+ar, dy+ar], start=225, end=315, fill='#2196F3', width=2)
            d.ellipse([cx-3, int(s*.12), cx+3, int(s*.18)], fill='#2196F3')
        d.rectangle([cx-int(s*.03), cy+ry, cx+int(s*.03), cy+ry+int(s*.10)], fill='#90A4AE')
        return self._shadow(img)

    def _iot(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        d.rounded_rectangle([int(s*.15), int(s*.20), int(s*.85), int(s*.70)],
                            radius=int(s*.03), fill='#00695C', outline='#004D40', width=2)
        chip_s = int(s*.15)
        chip_x = s//2 - chip_s//2
        chip_y = int(s*.38)
        d.rectangle([chip_x, chip_y, chip_x+chip_s, chip_y+chip_s],
                    fill='#1A1A1A', outline='#333333')
        for i in range(4):
            px = chip_x + 3 + i*(chip_s//4)
            d.line([(px, chip_y), (px, chip_y-4)], fill='#AAAAAA', width=1)
            d.line([(px, chip_y+chip_s), (px, chip_y+chip_s+4)], fill='#AAAAAA', width=1)
        ant_x = int(s*.75)
        d.line([(ant_x, int(s*.20)), (ant_x, int(s*.05))], fill='#AAAAAA', width=2)
        d.ellipse([ant_x-3, int(s*.02), ant_x+3, int(s*.08)], fill='#CCCCCC')
        if status == 'online':
            for i in range(2):
                ar = int(s*(0.06+i*0.06))
                d.arc([ant_x-ar, int(s*.05)-ar, ant_x+ar, int(s*.05)+ar],
                      start=270, end=360, fill='#76FF03', width=1)
        self._led(d, int(s*.22), int(s*.27), status)
        return self._shadow(img)

    def _unknown(self, s: int, status: str) -> Image.Image:
        img, d = self._canvas(s)
        cx = cy = s//2
        r  = int(s*.35)
        d.ellipse([cx-r, cy-r, cx+r, cy+r], fill='#616161', outline='#424242', width=2)
        try:
            qf  = ImageFont.truetype('arial.ttf', int(s*.40))
        except Exception:
            qf  = self._font
        bb  = d.textbbox((0, 0), '?', font=qf)
        tw  = bb[2]-bb[0]
        th  = bb[3]-bb[1]
        d.text((cx-tw//2, cy-th//2-2), '?', fill='white', font=qf)
        self._led(d, cx+r-3, cy-r+5, status)
        return self._shadow(img)