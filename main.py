import os
import sys
import customtkinter as ctk


def check_root() -> bool:
    if os.name == 'nt':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def main():
    
    root = check_root()
    if not root:
        print('test')

    ctk.set_appearance_mode('dark')
    ctk.set_default_color_theme('blue')

    from gui import NetMapApp
    app = NetMapApp(root)
    app.mainloop()


if __name__ == '__main__':
    main()