import os
import re
import sys
import json
import base64
import hashlib
import shutil
import ctypes
import subprocess
import tempfile
import mmap
import io
from datetime import datetime

# Don't Forget To Install Necessary Components
# pip install PyQt6 Pillow pillow-jxl-plugin pywin32 pyinstaller

# Hide the console window immediately when launched via python.exe on Windows
if os.name == "nt":
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
        # Ensure Windows Taskbar displays our custom icon instead of python.exe icon
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ByteWrapper.SFXConstructor.1.0")
    except Exception:
        pass

# Display unexpected startup errors instead of failing silently with a hidden console.
def _show_uncaught_error(exc_type, exc_value, exc_tb):
    import traceback
    details = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log_file = os.path.join(tempfile.gettempdir(), "byte_wrapper_error.log")
    try:
        with open(log_file, "w", encoding="utf-8") as log:
            log.write(details)
    except OSError:
        pass
    sys.__excepthook__(exc_type, exc_value, exc_tb)
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                "Byte Wrapper encountered an error:\n\n"
                + str(exc_value) + "\n\nDetails: " + log_file,
                "Byte Wrapper Error", 0x10,
            )
        except Exception:
            pass


sys.excepthook = _show_uncaught_error


from PyQt6.QtCore import Qt, QPoint, QThread, pyqtSignal, QSize, QTimer
from PyQt6.QtGui import (
    QIcon, QPixmap, QDragEnterEvent, QDropEvent, QPainter, QColor, QBrush, QPen
)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QProgressBar,
    QFileDialog, QMenu, QMessageBox
)

from PIL import Image, ImageDraw
try:
    import pillow_jxl  # Support for .jxl files
except ImportError:
    pass


# ==========================================
# BYTEHIDDEN.VBS - EMBEDDED SCRIPT (EDIT BELOW)
# ==========================================
# This text is written to the SFX archive only when Hidden Run is enabled.
# Edit the VBScript between triple quotes and rebuild the package to apply.
# No separate ByteHidden.vbs file is required.
BYTE_HIDDEN_VBS = r'''Option Explicit
' Byte Wrapper script launcher, embedded in the Python source.
' Edit the BYTE_HIDDEN_VBS block in Python and rebuild to apply changes.
' You can add MsgBox statements here. They will remain visible, while the
' BAT/CMD/PowerShell console window is not displayed.

Dim shell, fso, scriptPath, scriptExt, command, parameters, exitCode, i

If WScript.Arguments.Count < 1 Then
    MsgBox "No script path was provided.", vbExclamation, "Byte Wrapper"
    WScript.Quit 2
End If

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
scriptPath = WScript.Arguments(0)

If Not fso.FileExists(scriptPath) Then
    MsgBox "Script not found: " & scriptPath, vbCritical, "Byte Wrapper"
    WScript.Quit 2
End If

scriptExt = LCase(fso.GetExtensionName(scriptPath))
parameters = ""
For i = 1 To WScript.Arguments.Count - 1
    parameters = parameters & " " & Chr(34) & Replace(WScript.Arguments(i), Chr(34), Chr(34) & Chr(34)) & Chr(34)
Next

Select Case scriptExt
    Case "bat", "cmd"
        ' The outer quotes allow cmd.exe /S /C to preserve a quoted path.
        command = "cmd.exe /D /S /C " & Chr(34) & Chr(34) & scriptPath & Chr(34) & parameters & Chr(34)
    Case "ps1"
        command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File " & Chr(34) & scriptPath & Chr(34) & parameters
    Case Else
        MsgBox "Only BAT, CMD and PS1 scripts are supported.", vbExclamation, "Byte Wrapper"
        WScript.Quit 2
End Select

shell.CurrentDirectory = fso.GetParentFolderName(scriptPath)
' Example: MsgBox "Running: " & fso.GetFileName(scriptPath), vbInformation, "Byte Wrapper"
exitCode = shell.Run(command, 0, True)
' Example: MsgBox "Finished with exit code: " & exitCode, vbInformation, "Byte Wrapper"
WScript.Quit exitCode
'''


# ==========================================
# SFX CONFIG READER
# ==========================================
def process_file(file_path):
    """Open real 7-Zip SFX configs or Byte Wrapper's embedded C# source in Notepad.

    This is inspection only: changes saved in Notepad do not change the EXE.
    The file itself is never executed.
    Returns a (success, explanation) tuple for the GUI.
    """
    sources = (
        (b';!@Install@!UTF-8!', b';!@InstallEnd@!', '7-Zip SFX config'),
        (b';!@Install@!', b';!@InstallEnd@!', '7-Zip SFX config'),
        (b';!@ByteWrapperSource@UTF-8!', b';!@ByteWrapperSourceEnd@!',
         'Byte Wrapper generated C# source'),
    )
    try:
        if not os.path.isfile(file_path):
            return False, 'The selected EXE / SFX file does not exist.'
        if os.path.getsize(file_path) == 0:
            return False, 'The selected file is empty.'
        with open(file_path, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            content = None
            source_type = ''
            for start_marker, end_marker, description in sources:
                start_idx = data.find(start_marker)
                if start_idx < 0:
                    continue
                end_idx = data.find(end_marker, start_idx + len(start_marker))
                if end_idx < 0:
                    return False, 'A configuration start marker was found, but the end marker is missing.'
                if end_idx - start_idx > 2 * 1024 * 1024:
                    return False, 'The embedded configuration is too large to preview safely.'
                content = bytes(data[start_idx:end_idx + len(end_marker)]).decode('utf-8-sig', errors='replace')
                source_type = description
                break
        if content is None:
            return False, ('No supported 7-Zip SFX configuration or Byte Wrapper source was found. '
                           'Normal EXE files do not necessarily contain readable source code. '
                           'Byte Wrapper source previews are available in packages built with this update.')

        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8-sig', suffix='.txt', prefix='byte_wrapper_code_',
            delete=False
        ) as output:
            output.write(f'File: {os.path.basename(file_path)}\n')
            output.write(f'Type: {source_type}\n')
            output.write('View only: saving this text will not modify the EXE.\n')
            output.write('=' * 60 + '\n\n')
            output.write(content)
            output_file = output.name
        subprocess.Popen(['notepad.exe', output_file])
        return True, output_file
    except Exception as exc:
        return False, f'Unable to open SFX code: {exc}'


# ==========================================
# PASSWORD ENCRYPTION FOR EXPORT / IMPORT
# ==========================================
SECRET_EXPORT_KEY = b"ByteWrapper_Config_Cipher_Key_2026"


def encrypt_password_for_export(plain_text: str) -> str:
    if not plain_text:
        return ""
    raw = plain_text.encode("utf-8")
    key_stream = hashlib.sha256(SECRET_EXPORT_KEY).digest()
    encrypted = bytearray(len(raw))
    for i, b in enumerate(raw):
        encrypted[i] = b ^ key_stream[i % len(key_stream)] ^ ((i * 31) & 0xFF)
    return "ENC:" + base64.urlsafe_b64encode(bytes(encrypted)).decode("ascii")


def decrypt_password_from_import(cipher_text: str) -> str:
    if not cipher_text:
        return ""
    if not cipher_text.startswith("ENC:"):
        return cipher_text
    try:
        b64_part = cipher_text[4:]
        encrypted = base64.urlsafe_b64decode(b64_part.encode("ascii"))
        key_stream = hashlib.sha256(SECRET_EXPORT_KEY).digest()
        decrypted = bytearray(len(encrypted))
        for i, b in enumerate(encrypted):
            decrypted[i] = b ^ key_stream[i % len(key_stream)] ^ ((i * 31) & 0xFF)
        return decrypted.decode("utf-8")
    except Exception:
        return ""


# ==========================================
# ICON UTILITIES - DRAWN DEFAULT ICON
# ==========================================
# The default box is drawn with Pillow at runtime; there is no embedded ICO,
# zlib stream or external icon file. The generated ICO is used for
# SFX EXEs; the GUI instead loads its largest layer into a QPixmap.
def draw_default_sfx_icon(out_ico_path: str) -> None:
    """Render the user's clean line-art parcel icon as a multi-size Windows ICO.

    Geometry is drawn at 1024 px (smooth edges), then downsampled for Windows.
    No external image or embedded Base64 data is needed.
    """
    canvas = 1024
    factor = canvas / 214.0

    def xy(x, y):
        return (round(x * factor), round(y * factor))

    def poly(points, fill):
        draw.polygon([xy(*point) for point in points], fill=fill)

    def stroke(points, width=6):
        coords = [xy(*point) for point in points]
        draw.line(coords, fill=ink, width=round(width * factor), joint='curve')
        # Round exposed ends/corners to avoid harsh pixels when downsampled.
        r = width * factor / 2
        for cx, cy in (coords[0], coords[-1]):
            draw.ellipse((round(cx-r), round(cy-r), round(cx+r), round(cy+r)), fill=ink)

    img = Image.new('RGBA', (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    ink = '#414141'
    face = '#ffffff'

    # White panels stay legible against the GUI's dark background.
    poly([(12, 53), (105, 15), (198, 53), (106, 96)], face)  # top
    poly([(12, 53), (106, 96), (106, 205), (12, 162)], face)  # left
    poly([(106, 96), (198, 53), (198, 162), (106, 205)], face)  # right

    # Outer contour and three visible vertical/fold edges.
    stroke([(12, 53), (105, 15), (198, 53), (198, 162),
            (106, 205), (12, 162), (12, 53)], width=6.5)
    stroke([(12, 53), (106, 96), (198, 53)], width=6.5)
    stroke([(106, 96), (106, 205)], width=6.5)

    # Two top stripes and the vertical flap on the right face.
    stroke([(43, 40), (138, 80)], width=5.8)
    stroke([(76, 27), (166, 68)], width=5.8)
    stroke([(139, 80), (139, 120), (166, 110), (166, 68)], width=6)

    icon = img.resize((256, 256), Image.Resampling.LANCZOS)
    icon.save(out_ico_path, format='ICO',
              sizes=[(256, 256), (128, 128), (64, 64),
                     (48, 48), (32, 32), (16, 16)])

def get_app_icon_path() -> str:
    """Return a reusable, drawn default ICO without unpacking embedded data."""
    icon_path = os.path.join(tempfile.gettempdir(), "byte_wrapper_vector_box_v3.ico")
    if os.path.isfile(icon_path):
        try:
            with Image.open(icon_path) as existing:
                if existing.format == "ICO" and existing.size[0] >= 128:
                    return icon_path
        except (OSError, ValueError):
            pass
    try:
        # Atomic replacement prevents partial icons during concurrent launches.
        with tempfile.NamedTemporaryFile(prefix="bw_icon_", suffix=".ico",
                                         dir=tempfile.gettempdir(), delete=False) as tmp:
            pending_path = tmp.name
        try:
            draw_default_sfx_icon(pending_path)
            os.replace(pending_path, icon_path)
        finally:
            if os.path.isfile(pending_path):
                os.unlink(pending_path)
        return icon_path
    except (OSError, ValueError) as exc:
        # The program should still open even when TEMP is not writable.
        print("Unable to create drawn icon:", exc, file=sys.stderr)
        return ""



def load_crisp_gui_icon(ico_path: str) -> QIcon:
    """Use the largest ICO layer as a high-resolution in-memory GUI image.

    Qt may otherwise pick a 16x16 ICO layer, which looks blurry when the
    36x36 header logo or 24x24 selection button scales it upward.
    """
    if not ico_path:
        return QIcon()
    try:
        with Image.open(ico_path) as source:
            if source.format == 'ICO' and hasattr(source, 'ico'):
                sizes = source.ico.sizes()
                largest = max(sizes, key=lambda pair: pair[0] * pair[1])
                raster = source.ico.getimage(largest).convert('RGBA')
            else:
                raster = source.convert('RGBA')
            stream = io.BytesIO()
            raster.save(stream, format='PNG')
        pixmap = QPixmap()
        if pixmap.loadFromData(stream.getvalue(), 'PNG') and not pixmap.isNull():
            return QIcon(pixmap)
    except (OSError, ValueError, AttributeError):
        pass
    return QIcon(ico_path)


def extract_icon_from_file(file_path: str, out_ico_path: str) -> bool:
    """
    Extracts the icon from an .exe or associated file using Windows API
    (ExtractIconEx or ExtractAssociatedIcon) and saves it as a multi-size .ico.
    """
    try:
        import win32ui
        import win32gui
        import win32con
        import win32api

        ico_x = win32api.GetSystemMetrics(win32con.SM_CXICON)
        ico_y = win32api.GetSystemMetrics(win32con.SM_CYICON)

        hicon = 0
        large, small = [], []
        try:
            large, small = win32gui.ExtractIconEx(file_path, 0)
            if large:
                hicon = large[0]
            elif small:
                hicon = small[0]
        except Exception:
            pass

        # Fallback to ExtractAssociatedIconW via shell32 for scripts (.cmd, .bat, .ps1, etc.)
        if not hicon:
            buf = ctypes.create_unicode_buffer(file_path, 260)
            pi_icon = ctypes.c_uint16(0)
            hicon = ctypes.windll.shell32.ExtractAssociatedIconW(
                0, buf, ctypes.byref(pi_icon)
            )

        if not hicon:
            return False

        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, ico_x, ico_y)
        hdc = hdc.CreateCompatibleDC()
        hdc.SelectObject(hbmp)
        hdc.DrawIcon((0, 0), hicon)

        bmpinfo = hbmp.GetInfo()
        bmpstr = hbmp.GetBitmapBits(True)
        img = Image.frombuffer(
            "RGBA",
            (bmpinfo["bmWidth"], bmpinfo["bmHeight"]),
            bmpstr, "raw", "BGRA", 0, 1
        )
        img.save(out_ico_path, format="ICO", sizes=[(256, 256), (64, 64), (32, 32), (16, 16)])

        for h in large:
            win32gui.DestroyIcon(h)
        for h in small:
            win32gui.DestroyIcon(h)
        if not large and not small and hicon:
            ctypes.windll.user32.DestroyIcon(hicon)
        return True
    except Exception:
        return False


def convert_image_to_ico(src_path: str, out_ico_path: str) -> bool:
    """Converts PNG, JPG, JPEG, JXL, or ICO files into a standard Windows .ico file."""
    try:
        img = Image.open(src_path).convert("RGBA")
        img.save(out_ico_path, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
        return True
    except Exception:
        return False


# ==========================================
# SMART CLICKABLE & DRAG-DROP LINE EDIT
# ==========================================
class SmartLineEdit(QLineEdit):
    """
    Supports direct typing, drag-and-drop, and pops up an English selection menu
    when clicked or right-clicked.
    """
    def __init__(self, placeholder="", mode="source", parent_win=None):
        super().__init__(parent_win)
        self.setPlaceholderText(placeholder)
        self.mode = mode
        self.parent_win = parent_win
        self.setAcceptDrops(True)
        self.setFixedHeight(34)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if event.button() == Qt.MouseButton.LeftButton:
            self.open_selector()

    def contextMenuEvent(self, event):
        self.open_selector()

    def _create_styled_menu(self) -> QMenu:
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #131b24;
                color: #e2e8f0;
                border: 1px solid #263445;
                padding: 4px;
                font-size: 12px;
            }
            QMenu::item {
                padding: 6px 18px;
                border-radius: 3px;
            }
            QMenu::item:selected {
                background-color: #2563eb;
                color: #ffffff;
            }
            QMenu::separator {
                height: 1px;
                background: #222f3e;
                margin: 4px 0px;
            }
        """)
        return menu

    def open_selector(self):
        if not self.isEnabled():
            return

        menu = self._create_styled_menu()

        if self.mode == "source":
            act_folder = menu.addAction("1. Select Folder...")
            act_file = menu.addAction("2. Select File...")
            menu.addSeparator()
            act_manual = menu.addAction("Type Manually")
            action = menu.exec(self.mapToGlobal(QPoint(0, self.height())))
            if action == act_folder:
                folder = QFileDialog.getExistingDirectory(self, "Select Source Folder")
                if folder:
                    self.setText(os.path.normpath(folder))
            elif action == act_file:
                file_path, _ = QFileDialog.getOpenFileName(self, "Select Source File")
                if file_path:
                    self.setText(os.path.normpath(file_path))
            elif action == act_manual:
                self.setFocus()

        elif self.mode == "extract_to":
            act_folder = menu.addAction("1. Select Folder...")
            act_temp = menu.addAction("2. %Temp%")
            act_sysdrive = menu.addAction("3. %SystemDrive%")
            act_progfiles = menu.addAction("4. %SystemDrive%\\Program Files")
            menu.addSeparator()
            act_manual = menu.addAction("Type Manually")

            action = menu.exec(self.mapToGlobal(QPoint(0, self.height())))
            if action == act_folder:
                folder = QFileDialog.getExistingDirectory(self, "Select Extraction Folder")
                if folder:
                    self.setText(os.path.normpath(folder))
            elif action == act_temp:
                self.setText("%Temp%")
            elif action == act_sysdrive:
                self.setText("%SystemDrive%")
            elif action == act_progfiles:
                self.setText("%SystemDrive%\\Program Files")
            elif action == act_manual:
                self.setFocus()

        elif self.mode == "output":
            act_folder = menu.addAction("1. Select Folder...")
            act_desktop = menu.addAction("2. %UserProfile%\\Desktop")
            menu.addSeparator()
            act_manual = menu.addAction("Type Manually")

            action = menu.exec(self.mapToGlobal(QPoint(0, self.height())))
            if action == act_folder:
                folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
                if folder:
                    self.setText(os.path.normpath(folder))
            elif action == act_desktop:
                self.setText("%UserProfile%\\Desktop")
            elif action == act_manual:
                self.setFocus()

        elif self.mode == "run_file":
            act_file = menu.addAction("1. Select Executable / Script File...")
            menu.addSeparator()
            act_manual = menu.addAction("Type Command / Path Manually")

            action = menu.exec(self.mapToGlobal(QPoint(0, self.height())))
            if action == act_file:
                start_dir = ""
                if self.parent_win:
                    src = os.path.expandvars(self.parent_win.inp_source.text().strip())
                    if os.path.isdir(src):
                        start_dir = src
                    elif os.path.isfile(src):
                        start_dir = os.path.dirname(src)

                file_path, _ = QFileDialog.getOpenFileName(
                    self, "Select File to Run After Extraction", start_dir
                )
                if file_path:
                    norm_file = os.path.normpath(file_path)
                    if start_dir and norm_file.lower().startswith(os.path.normpath(start_dir).lower()):
                        rel_path = os.path.relpath(norm_file, start_dir)
                        ext_to = self.parent_win.inp_extract.text().strip() if self.parent_win else ""
                        if ext_to:
                            self.setText(os.path.join(ext_to, rel_path))
                        else:
                            self.setText(rel_path)
                    else:
                        self.setText(norm_file)
            elif action == act_manual:
                self.setFocus()

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                local_path = urls[0].toLocalFile()
                if local_path:
                    self.setText(os.path.normpath(local_path))
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class SFXDropLogo(QLabel):
    """Clickable header logo which also accepts local .exe/.sfx file drops."""
    fileDropped = pyqtSignal(str)

    @staticmethod
    def _first_eligible_file(event):
        if not event.mimeData().hasUrls():
            return ''
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if path and os.path.isfile(path) and os.path.splitext(path)[1].lower() in ('.exe', '.sfx'):
                return os.path.normpath(path)
        return ''

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setToolTip('Click to inspect an EXE/SFX or drop it here to open its config in Notepad.')

    def dragEnterEvent(self, event):
        if self._first_eligible_file(event):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if self._first_eligible_file(event):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        path = self._first_eligible_file(event)
        if path:
            self.fileDropped.emit(path)
            event.acceptProposedAction()
        else:
            event.ignore()


# ==========================================
# BACKGROUND SFX BUILDER THREAD
# ==========================================
class SFXBuilderWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, config: dict):
        super().__init__()
        self.cfg = config

    def find_7zip(self) -> str:
        candidates = [
            shutil.which("7z"),
            r"C:\Program Files\7-Zip\7z.exe",
            r"C:\Program Files (x86)\7-Zip\7z.exe",
        ]
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return ""

    def find_csc(self) -> str:
        """Finds the built-in Windows .NET Framework C# compiler (csc.exe)."""
        win_dir = os.environ.get("SystemRoot", r"C:\Windows")
        candidates = [
            os.path.join(win_dir, r"Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
            os.path.join(win_dir, r"Microsoft.NET\Framework\v4.0.30319\csc.exe"),
            shutil.which("csc"),
        ]
        for c in candidates:
            if c and os.path.isfile(c):
                return c
        return ""

    def resolve_output_exe_path(self) -> str:
        raw_out_dir = self.cfg["output"].strip().replace("/", "\\")
        out_dir = os.path.expandvars(raw_out_dir)
        os.makedirs(out_dir, exist_ok=True)

        name = self.cfg["name"].strip() or "Package"
        if name.lower().endswith(".exe"):
            name = name[:-4]

        target_path = os.path.join(out_dir, f"{name}.exe")

        if self.cfg["dont_replace"] and os.path.exists(target_path):
            now_dt = datetime.now()
            # 24-hour format DD.MM.YYYY HH.MM.SS (safe for Windows filenames)
            fs_stamp = now_dt.strftime("%d.%m.%Y %H.%M.%S")
            target_path = os.path.join(out_dir, f"{name}_{fs_stamp}.exe")

        return target_path

    def generate_helper_scripts(self, work_dir: str) -> list:
        """Write the editable VBS text embedded at the top of this Python script."""
        if not self.cfg['hidden_run']:
            return []
        packaged_vbs = os.path.join(work_dir, '_byte_hidden.vbs')
        with open(packaged_vbs, 'w', encoding='utf-8', newline='\r\n') as output:
            output.write(BYTE_HIDDEN_VBS)
        return [packaged_vbs]

    def get_internal_7z_password(self) -> str:
        """
        Determines the internal 7-Zip encryption password:
        - If user Password is set, uses that password.
        - If Crypto is enabled, uses "byte" silently in the background.
        """
        if self.cfg["use_password"] and self.cfg["password"]:
            return self.cfg["password"]
        if self.cfg["crypto"]:
            return "byte"
        return ""

    def build_7z_archive(self, seven_zip: str, source_path: str, archive_path: str, extra_files: list) -> subprocess.CompletedProcess:
        cmd = [seven_zip, "a"]

        if self.cfg["compress"]:
            # 7z format, 9-ultra, lzma2, dict 256mb, word size 64, solid 16g, max cpu threads
            cmd.extend([
                "-t7z",
                "-mx=9",
                "-m0=lzma2",
                "-md=256m",
                "-mfb=64",
                "-ms=16g",
                "-mmt=on"
            ])
        else:
            cmd.extend(["-t7z", "-mx=1", "-mmt=on"])

        internal_pw = self.get_internal_7z_password()
        if internal_pw:
            # -mhe=on encrypts archive headers so filenames are never visible in 7-Zip
            cmd.extend([f"-p{internal_pw}", "-mhe=on"])

        cmd.extend(["-y", archive_path])

        if os.path.isdir(source_path):
            cmd.append(os.path.join(source_path, "*"))
        else:
            cmd.append(source_path)

        cmd.extend(extra_files)
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        return subprocess.run(cmd, capture_output=True, text=True, creationflags=creation_flags)

    def obfuscate_payload(self, raw_7z_path: str, out_dat_path: str) -> bool:
        """
        When Crypto is enabled, scrambles the binary payload and 7z signature
        so the encrypted package is not directly readable by 7-Zip.
        """
        should_scramble = self.cfg["crypto"]
        key_bytes = b"byte_wrapper_secret_key_2026"
        key_len = len(key_bytes)

        with open(raw_7z_path, "rb") as fin:
            data = bytearray(fin.read())

        if should_scramble:
            for i in range(len(data)):
                data[i] ^= key_bytes[i % key_len] ^ ((i & 0xFF) ^ 0xA5)

        with open(out_dat_path, "wb") as fout:
            fout.write(data)

        return should_scramble

    def compile_csharp_sfx(self, csc_path: str, work_dir: str, payload_dat: str, scrambled: bool, seven_zip: str, target_exe: str) -> tuple[bool, str]:
        shutil.copy2(seven_zip, os.path.join(work_dir, "7z.exe"))
        seven_zip_dll = os.path.join(os.path.dirname(seven_zip), "7z.dll")
        has_dll = os.path.isfile(seven_zip_dll)
        if has_dll:
            shutil.copy2(seven_zip_dll, os.path.join(work_dir, "7z.dll"))

        src_norm = os.path.normpath(os.path.expandvars(self.cfg["source"].strip()))
        source_folder_name = os.path.basename(src_norm) if os.path.isdir(src_norm) else ""

        def cs_escape(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')

        prod_name_str = cs_escape(self.cfg["name"].strip() or "Byte Wrapper Package")
        # Windows Explorer reads 'File description' from AssemblyTitle!
        # If Description is provided, set AssemblyTitle & AssemblyDescription to Description.
        raw_desc = self.cfg["description"].strip()
        file_desc_str = cs_escape(raw_desc if raw_desc else (self.cfg["name"].strip() or "Byte Wrapper Package"))

        extract_to_str = cs_escape(self.cfg["extract_to"].strip())
        run_file_str = cs_escape(self.cfg["run_file"].strip())
        source_folder_name_str = cs_escape(source_folder_name)

        internal_7z_pw = cs_escape(self.get_internal_7z_password())
        ask_user_pw = "true" if (self.cfg["use_password"] and bool(self.cfg["password"])) else "false"
        expected_user_pw = cs_escape(self.cfg["password"])

        is_scrambled = "true" if scrambled else "false"
        hidden_run = "true" if self.cfg["hidden_run"] else "false"
        extract_only = "true" if self.cfg["extract_only"] else "false"
        instances = "true" if self.cfg["instances"] else "false"
        self_remove = "true" if self.cfg["self_remove"] else "false"
        show_progress = "true" if self.cfg["progress_bar"] else "false"

        exec_level = "requireAdministrator" if self.cfg["run_as_admin"] else "asInvoker"
        manifest_path = os.path.join(work_dir, "app.manifest")
        manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="1.0.0.0" name="ByteWrapper.Package"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="{exec_level}" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"""
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest_xml)

        cs_code = f"""
using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Reflection;
using System.Diagnostics;
using System.Windows.Forms;

[assembly: AssemblyTitle("{file_desc_str}")]
[assembly: AssemblyDescription("{file_desc_str}")]
[assembly: AssemblyProduct("{prod_name_str}")]
[assembly: AssemblyCompany("Byte Wrapper")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace ByteWrapperStub
{{
    static class Program
    {{
        private static readonly string EXTRACT_TO = "{extract_to_str}";
        private static readonly string RUN_FILE = "{run_file_str}";
        private static readonly string SOURCE_FOLDER_NAME = "{source_folder_name_str}";
        private static readonly string INTERNAL_7Z_PW = "{internal_7z_pw}";
        private static readonly bool ASK_USER_PW = {ask_user_pw};
        private static readonly string EXPECTED_USER_PW = "{expected_user_pw}";
        private static readonly bool IS_SCRAMBLED = {is_scrambled};
        private static readonly bool HIDDEN_RUN = {hidden_run};
        private static readonly bool EXTRACT_ONLY = {extract_only};
        private static readonly bool INSTANCES = {instances};
        private static readonly bool SELF_REMOVE = {self_remove};
        private static readonly bool SHOW_PROGRESS = {show_progress};

        [STAThread]
        static void Main()
        {{
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (ASK_USER_PW)
            {{
                string inputPw = PromptPassword();
                if (inputPw == null)
                    return;
                if (inputPw != EXPECTED_USER_PW)
                {{
                    MessageBox.Show("Invalid password!", "{prod_name_str}", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }}
            }}

            string targetDir = string.IsNullOrWhiteSpace(EXTRACT_TO)
                ? Path.Combine(Path.GetTempPath(), "BytePkg_" + Guid.NewGuid().ToString("N").Substring(0, 8))
                : Environment.ExpandEnvironmentVariables(EXTRACT_TO.Replace("/", "\\\\"));

            if (!string.IsNullOrEmpty(SOURCE_FOLDER_NAME) && !string.IsNullOrEmpty(RUN_FILE))
            {{
                string expandedRun = Environment.ExpandEnvironmentVariables(RUN_FILE.Replace("/", "\\\\"));
                string expectedSub = Path.Combine(targetDir, SOURCE_FOLDER_NAME);
                if (expandedRun.StartsWith(expectedSub + "\\\\", StringComparison.OrdinalIgnoreCase) &&
                    !targetDir.EndsWith(SOURCE_FOLDER_NAME, StringComparison.OrdinalIgnoreCase))
                {{
                    targetDir = expectedSub;
                }}
            }}

            try
            {{
                Directory.CreateDirectory(targetDir);
            }}
            catch (Exception ex)
            {{
                MessageBox.Show("Failed to create target directory: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }}

            string workTemp = Path.Combine(Path.GetTempPath(), "bw_rt_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(workTemp);

            Form progressForm = null;
            if (SHOW_PROGRESS && !HIDDEN_RUN)
            {{
                progressForm = CreateProgressForm();
                progressForm.Show();
                Application.DoEvents();
            }}

            try
            {{
                string sevenZExe = Path.Combine(workTemp, "7z.exe");
                string sevenZDll = Path.Combine(workTemp, "7z.dll");
                string archive7z = Path.Combine(workTemp, "pkg.7z");

                ExtractResource("7z.exe", sevenZExe, false);
                ExtractResourceIfExists("7z.dll", sevenZDll, false);
                ExtractResource("payload.dat", archive7z, IS_SCRAMBLED);

                Application.DoEvents();

                StringBuilder args = new StringBuilder();
                args.Append("x \\"" + archive7z + "\\" ");
                args.Append("-o\\"" + targetDir + "\\" ");
                if (!string.IsNullOrEmpty(INTERNAL_7Z_PW))
                {{
                    args.Append("-p\\"" + INTERNAL_7Z_PW + "\\" ");
                }}
                args.Append(INSTANCES ? "-aos -y" : "-aoa -y");

                ProcessStartInfo psi7z = new ProcessStartInfo();
                psi7z.FileName = sevenZExe;
                psi7z.Arguments = args.ToString();
                psi7z.UseShellExecute = false;
                psi7z.CreateNoWindow = true;
                psi7z.WindowStyle = ProcessWindowStyle.Hidden;

                using (Process p = Process.Start(psi7z))
                {{
                    while (!p.WaitForExit(50))
                    {{
                        Application.DoEvents();
                    }}
                }}

                if (progressForm != null)
                {{
                    progressForm.Close();
                    progressForm.Dispose();
                    progressForm = null;
                }}

                if (!EXTRACT_ONLY && !string.IsNullOrWhiteSpace(RUN_FILE))
                {{
                    ExecuteRunFile(targetDir);
                }}
            }}
            finally
            {{
                if (progressForm != null)
                {{
                    progressForm.Close();
                    progressForm.Dispose();
                }}
                TryDelete(Path.Combine(targetDir, "_byte_hidden.vbs"));
                try {{ Directory.Delete(workTemp, true); }} catch {{ }}
            }}

            if (SELF_REMOVE)
            {{
                SelfDeleteExe();
            }}
        }}

        private static void ExecuteRunFile(string targetDir)
        {{
            string rawCmd = Environment.ExpandEnvironmentVariables(RUN_FILE.Trim().Replace("/", "\\\\"));
            string resolvedFile = "";
            string arguments = "";

            if (File.Exists(rawCmd))
            {{
                resolvedFile = rawCmd;
            }}
            else if (File.Exists(Path.Combine(targetDir, rawCmd)))
            {{
                resolvedFile = Path.Combine(targetDir, rawCmd);
            }}
            else
            {{
                string candidatePath = rawCmd;
                if (rawCmd.StartsWith("\\""))
                {{
                    int endQuote = rawCmd.IndexOf('\\"', 1);
                    if (endQuote > 1)
                    {{
                        candidatePath = rawCmd.Substring(1, endQuote - 1);
                        arguments = rawCmd.Substring(endQuote + 1).Trim();
                    }}
                }}
                else
                {{
                    int spaceIdx = rawCmd.IndexOf(' ');
                    if (spaceIdx > 0)
                    {{
                        string firstPart = rawCmd.Substring(0, spaceIdx);
                        if (File.Exists(firstPart) || File.Exists(Path.Combine(targetDir, firstPart)) || firstPart.Contains("."))
                        {{
                            candidatePath = firstPart;
                            arguments = rawCmd.Substring(spaceIdx + 1).Trim();
                        }}
                    }}
                    // Paths selected in the GUI may contain unquoted spaces.
                    // Find the script extension before optional parameters.
                    string[] knownExtensions = new string[] {{ ".bat", ".cmd", ".ps1", ".exe", ".reg" }};
                    foreach (string knownExtension in knownExtensions)
                    {{
                        int extAt = rawCmd.IndexOf(knownExtension, StringComparison.OrdinalIgnoreCase);
                        if (extAt < 1) continue;
                        int endAt = extAt + knownExtension.Length;
                        if (endAt == rawCmd.Length || Char.IsWhiteSpace(rawCmd[endAt]))
                        {{
                            candidatePath = rawCmd.Substring(0, endAt);
                            arguments = rawCmd.Substring(endAt).Trim();
                            break;
                        }}
                    }}
                }}

                if (File.Exists(candidatePath))
                {{
                    resolvedFile = candidatePath;
                }}
                else if (File.Exists(Path.Combine(targetDir, candidatePath)))
                {{
                    resolvedFile = Path.Combine(targetDir, candidatePath);
                }}
                else
                {{
                    string fileNameOnly = Path.GetFileName(candidatePath);
                    if (!string.IsNullOrEmpty(fileNameOnly))
                    {{
                        string directMatch = Path.Combine(targetDir, fileNameOnly);
                        if (File.Exists(directMatch))
                        {{
                            resolvedFile = directMatch;
                        }}
                        else
                        {{
                            try
                            {{
                                string[] found = Directory.GetFiles(targetDir, fileNameOnly, SearchOption.AllDirectories);
                                if (found.Length > 0)
                                    resolvedFile = found[0];
                            }}
                            catch {{ }}
                        }}
                    }}
                }}
            }}

            string workDir = !string.IsNullOrEmpty(resolvedFile)
                ? Path.GetDirectoryName(resolvedFile)
                : targetDir;

            string finalCmdLine = !string.IsNullOrEmpty(resolvedFile)
                ? ("\\"" + resolvedFile + "\\"" + (string.IsNullOrEmpty(arguments) ? "" : " " + arguments))
                : rawCmd;

            string lowerCmd = finalCmdLine.ToLowerInvariant();
            string hiddenVbs = Path.Combine(targetDir, "_byte_hidden.vbs");

            if (lowerCmd.EndsWith(".reg\\"") || lowerCmd.EndsWith(".reg") || lowerCmd.Contains("regedit"))
            {{
                string regArgs = finalCmdLine;
                if (!lowerCmd.Contains("regedit"))
                    regArgs = (HIDDEN_RUN ? "/s " : "") + finalCmdLine;
                else if (HIDDEN_RUN && !lowerCmd.Contains("/s"))
                    regArgs = finalCmdLine.Replace("regedit.exe", "regedit.exe /s").Replace("regedit", "regedit /s");

                ProcessStartInfo psiReg = new ProcessStartInfo("regedit.exe", regArgs);
                psiReg.WorkingDirectory = workDir;
                psiReg.UseShellExecute = false;
                psiReg.CreateNoWindow = HIDDEN_RUN;
                if (HIDDEN_RUN) psiReg.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process p = Process.Start(psiReg)) {{ if (p != null) p.WaitForExit(); }}
                return;
            }}

            if (!string.IsNullOrEmpty(resolvedFile) && resolvedFile.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
            {{
                finalCmdLine = "powershell.exe -ExecutionPolicy Bypass -File " + finalCmdLine;
            }}

            if (!HIDDEN_RUN && !string.IsNullOrEmpty(resolvedFile) &&
                resolvedFile.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {{
                ProcessStartInfo psiExe = new ProcessStartInfo(resolvedFile, arguments);
                psiExe.WorkingDirectory = workDir;
                psiExe.UseShellExecute = true;
                using (Process p = Process.Start(psiExe)) {{ if (p != null) p.WaitForExit(); }}
                return;
            }}

            if (HIDDEN_RUN)
            {{
                // Hand the script path (and any optional arguments) directly to
                // the embedded ByteHidden.vbs; do NOT split cmd.exe /c into VBS args.
                if (string.IsNullOrEmpty(resolvedFile) || !File.Exists(resolvedFile))
                {{
                    MessageBox.Show("Run File was not found: " + RUN_FILE,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }}
                string runExt = Path.GetExtension(resolvedFile).ToLowerInvariant();
                if (runExt != ".bat" && runExt != ".cmd" && runExt != ".ps1")
                {{
                    MessageBox.Show("Hidden Run supports .bat, .cmd and .ps1 files only.",
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }}
                if (!File.Exists(hiddenVbs))
                {{
                    MessageBox.Show("ByteHidden.vbs was not included in the package.",
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }}
                ProcessStartInfo psiVbs = new ProcessStartInfo();
                psiVbs.FileName = "wscript.exe";
                psiVbs.Arguments = "//nologo \\"" + hiddenVbs + "\\" \\"" + resolvedFile + "\\"" +
                    (string.IsNullOrWhiteSpace(arguments) ? "" : " " + arguments);
                psiVbs.WorkingDirectory = workDir;
                psiVbs.UseShellExecute = false;
                psiVbs.CreateNoWindow = true;
                psiVbs.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process p = Process.Start(psiVbs))
                {{
                    if (p != null)
                    {{
                        p.WaitForExit();
                        if (p.ExitCode != 0)
                            MessageBox.Show("The script runner returned exit code " + p.ExitCode,
                                "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }}
                }}
            }}
            else
            {{
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c cd /d \\"" + workDir + "\\" && " + finalCmdLine;
                psi.WorkingDirectory = workDir;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = false;
                using (Process p = Process.Start(psi)) {{ if (p != null) p.WaitForExit(); }}
            }}
        }}

        private static void SelfDeleteExe()
        {{
            try
            {{
                string exePath = Application.ExecutablePath;
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c :loop & del /f /q \\"" + exePath + "\\" >nul 2>&1 & if exist \\"" + exePath + "\\" (ping 127.0.0.1 -n 2 >nul & goto loop)";
                psi.WorkingDirectory = Path.GetTempPath();
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }}
            catch {{ }}
        }}

        private static void TryDelete(string path)
        {{
            try {{ if (File.Exists(path)) File.Delete(path); }} catch {{ }}
        }}

        private static void ExtractResourceIfExists(string resName, string outPath, bool unscramble)
        {{
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
            {{
                if (s == null) return;
            }}
            ExtractResource(resName, outPath, unscramble);
        }}

        private static void ExtractResource(string resName, string outPath, bool unscramble)
        {{
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
            {{
                if (s == null)
                    throw new Exception("Resource not found: " + resName);
                byte[] buffer = new byte[s.Length];
                int read = 0;
                while (read < buffer.Length)
                {{
                    int r = s.Read(buffer, read, buffer.Length - read);
                    if (r <= 0) break;
                    read += r;
                }}

                if (unscramble)
                {{
                    byte[] key = Encoding.ASCII.GetBytes("byte_wrapper_secret_key_2026");
                    int klen = key.Length;
                    for (int i = 0; i < buffer.Length; i++)
                    {{
                        buffer[i] = (byte)(buffer[i] ^ key[i % klen] ^ ((i & 0xFF) ^ 0xA5));
                    }}
                }}

                File.WriteAllBytes(outPath, buffer);
            }}
        }}

        private static Form CreateProgressForm()
        {{
            Form f = new Form();
            f.Text = "{prod_name_str}";
            f.Size = new Size(340, 95);
            f.FormBorderStyle = FormBorderStyle.FixedDialog;
            f.StartPosition = FormStartPosition.CenterScreen;
            f.MaximizeBox = false;
            f.MinimizeBox = false;
            f.ControlBox = false;
            f.BackColor = Color.FromArgb(11, 16, 22);
            f.ForeColor = Color.FromArgb(226, 232, 240);

            Label lbl = new Label();
            lbl.Text = "Extracting package, please wait...";
            lbl.AutoSize = false;
            lbl.Bounds = new Rectangle(16, 14, 300, 20);
            lbl.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
            f.Controls.Add(lbl);

            ProgressBar pb = new ProgressBar();
            pb.Style = ProgressBarStyle.Marquee;
            pb.MarqueeAnimationSpeed = 25;
            pb.Bounds = new Rectangle(16, 40, 292, 18);
            f.Controls.Add(pb);

            return f;
        }}

        private static string PromptPassword()
        {{
            using (Form f = new Form())
            {{
                f.Text = "{prod_name_str} - Password Required";
                f.Size = new Size(330, 145);
                f.FormBorderStyle = FormBorderStyle.FixedDialog;
                f.StartPosition = FormStartPosition.CenterScreen;
                f.MaximizeBox = false;
                f.MinimizeBox = false;
                f.BackColor = Color.FromArgb(11, 16, 22);
                f.ForeColor = Color.FromArgb(226, 232, 240);

                Label lbl = new Label();
                lbl.Text = "Enter password to open package:";
                lbl.Bounds = new Rectangle(15, 12, 285, 20);
                lbl.Font = new Font("Segoe UI", 9F);
                f.Controls.Add(lbl);

                TextBox txt = new TextBox();
                txt.UseSystemPasswordChar = true;
                txt.Bounds = new Rectangle(15, 36, 285, 25);
                txt.BackColor = Color.FromArgb(19, 27, 35);
                txt.ForeColor = Color.White;
                f.Controls.Add(txt);

                Button btnOk = new Button();
                btnOk.Text = "OK";
                btnOk.DialogResult = DialogResult.OK;
                btnOk.Bounds = new Rectangle(135, 70, 75, 26);
                btnOk.FlatStyle = FlatStyle.Flat;
                f.Controls.Add(btnOk);

                Button btnCancel = new Button();
                btnCancel.Text = "Cancel";
                btnCancel.DialogResult = DialogResult.Cancel;
                btnCancel.Bounds = new Rectangle(220, 70, 80, 26);
                btnCancel.FlatStyle = FlatStyle.Flat;
                f.Controls.Add(btnCancel);

                f.AcceptButton = btnOk;
                f.CancelButton = btnCancel;

                if (f.ShowDialog() == DialogResult.OK)
                    return txt.Text;
                return null;
            }}
        }}
    }}
}}
"""
        cs_file = os.path.join(work_dir, "Stub.cs")
        with open(cs_file, "w", encoding="utf-8-sig") as f:
            f.write(cs_code)

        csc_cmd = [
            csc_path,
            "/nologo",
            "/target:winexe",
            "/optimize+",
            f"/out:{target_exe}",
            f"/win32manifest:{manifest_path}",
            f'/resource:{payload_dat},payload.dat',
            f'/resource:{os.path.join(work_dir, "7z.exe")},7z.exe',
        ]
        if has_dll:
            csc_cmd.append(f'/resource:{os.path.join(work_dir, "7z.dll")},7z.dll')

        # Always embed the selected icon or the internally drawn default box icon
        icon_ico = self.cfg.get("icon_ico", "")
        if not (icon_ico and os.path.isfile(icon_ico)):
            icon_ico = get_app_icon_path()
        if icon_ico and os.path.isfile(icon_ico):
            csc_cmd.append(f"/win32icon:{icon_ico}")

        csc_cmd.append(cs_file)

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        res = subprocess.run(csc_cmd, capture_output=True, text=True, creationflags=creation_flags)
        if res.returncode != 0 or not os.path.isfile(target_exe):
            return False, f"C# Stub Compilation Error:\n{res.stdout}\n{res.stderr}"
        # Retain the exact generated C# for the header-logo SFX code viewer.
        # Place it BEFORE the optional appended 7z archive so 7-Zip remains readable.
        with open(target_exe, 'ab') as output:
            output.write(b'\r\n;!@ByteWrapperSource@UTF-8!\r\n')
            output.write(cs_code.encode('utf-8'))
            output.write(b'\r\n;!@ByteWrapperSourceEnd@!\r\n')
        if not scrambled:
            # 7-Zip can inspect a normal .7z appended to an executable.
            with open(payload_dat, "rb") as archive, open(target_exe, "ab") as output:
                shutil.copyfileobj(archive, output)
        return True, target_exe

    def run(self):
        try:
            self.progress.emit(5)
            seven_zip = self.find_7zip()
            if not seven_zip:
                self.finished.emit(False, "7-Zip (7z.exe) was not found! Please make sure 7-Zip is installed.")
                return

            csc_path = self.find_csc()
            if not csc_path:
                self.finished.emit(False, "Windows .NET C# compiler (csc.exe) was not found!")
                return

            source_path = os.path.expandvars(self.cfg["source"].strip())
            if not os.path.exists(source_path):
                self.finished.emit(False, f"Source Folder / File path does not exist:\n{source_path}")
                return

            out_dir = os.path.expandvars(self.cfg["output"].strip())
            if not out_dir:
                self.finished.emit(False, "Please specify a valid Output save path!")
                return

            target_exe = self.resolve_output_exe_path()
            self.progress.emit(15)

            with tempfile.TemporaryDirectory(prefix="byte_wrapper_build_") as work_dir:
                extra_files = self.generate_helper_scripts(work_dir)
                self.progress.emit(25)

                raw_7z = os.path.join(work_dir, "raw_package.7z")
                res_7z = self.build_7z_archive(seven_zip, source_path, raw_7z, extra_files)
                if res_7z.returncode != 0:
                    self.finished.emit(False, f"7-Zip Compression Error:\n{res_7z.stderr or res_7z.stdout}")
                    return

                self.progress.emit(60)

                payload_dat = os.path.join(work_dir, "payload.dat")
                scrambled = self.obfuscate_payload(raw_7z, payload_dat)
                self.progress.emit(75)

                ok, msg = self.compile_csharp_sfx(csc_path, work_dir, payload_dat, scrambled, seven_zip, target_exe)
                if not ok:
                    self.finished.emit(False, msg)
                    return

                self.progress.emit(100)
                self.finished.emit(True, f"Package successfully created at:\n{target_exe}")

        except Exception as e:
            self.finished.emit(False, f"Unexpected error: {str(e)}")


# ==========================================
# MAIN APPLICATION WINDOW (BYTE WRAPPER GUI)
# ==========================================
class ByteWrapperWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Byte Wrapper")
        self.setFixedSize(380, 600)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.drag_pos = QPoint()

        # Always use the internally drawn vector-style box icon as the default
        # for the GUI and generated SFX files. Users can still override it later.
        self.app_icon_path = get_app_icon_path()
        if not self.app_icon_path or not os.path.isfile(self.app_icon_path):
            fallback_ico = os.path.join(tempfile.gettempdir(), "byte_wrapper_default_box.ico")
            self._save_fallback_box_ico(fallback_ico)
            self.app_icon_path = fallback_ico

        self.current_icon_source = self.app_icon_path
        self.converted_ico_path = self.app_icon_path

        # Keep the generated ICO for SFX compilation, but load its largest
        # resolution into Qt for a sharp title logo, button, and taskbar icon.
        self.default_gui_icon = load_crisp_gui_icon(self.app_icon_path)
        self.setWindowIcon(self.default_gui_icon)
        if QApplication.instance():
            QApplication.instance().setWindowIcon(self.default_gui_icon)

        self._user_edited_name = False
        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._on_blink_step)
        self._blink_step_count = 0

        self.init_ui()
        self.apply_styles()

    def _save_fallback_box_ico(self, out_ico: str):
        """Create the internal vector-style default icon."""
        draw_default_sfx_icon(out_ico)

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        # Uniform margins and spacing across the entire window
        main_layout.setContentsMargins(18, 14, 18, 18)
        main_layout.setSpacing(6)

        # --- HEADER ---
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 4)
        header_layout.setSpacing(10)

        self.logo_label = SFXDropLogo(self)
        self.logo_label.fileDropped.connect(self.inspect_sfx_file)
        # Scale from the 256px artwork (not a 16px ICO thumbnail). Render
        # at the display's actual physical pixel density to avoid DPI blur.
        logo_dpr = max(1.0, self.devicePixelRatioF())
        logo_size_px = max(36, round(36 * logo_dpr))
        logo_pix = self.default_gui_icon.pixmap(QSize(256, 256)).scaled(
            logo_size_px, logo_size_px,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        logo_pix.setDevicePixelRatio(logo_dpr)
        self.logo_label.setPixmap(logo_pix)
        self.logo_label.setFixedSize(36, 36)
        self.logo_label.setCursor(Qt.CursorShape.PointingHandCursor)
        self.logo_label.mousePressEvent = self.on_logo_clicked
        header_layout.addWidget(self.logo_label)

        title_layout = QVBoxLayout()
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(1)
        lbl_title = QLabel("Byte Wrapper")
        lbl_title.setObjectName("HeaderTitle")
        lbl_sub = QLabel("Create unattended & silent packages.")
        lbl_sub.setObjectName("HeaderSubtitle")
        title_layout.addWidget(lbl_title)
        title_layout.addWidget(lbl_sub)
        header_layout.addLayout(title_layout)

        header_layout.addStretch()

        btn_min = QPushButton("—")
        btn_min.setObjectName("WinControlBtn")
        btn_min.setFixedSize(26, 26)
        btn_min.clicked.connect(self.showMinimized)

        btn_close = QPushButton("✕")
        btn_close.setObjectName("WinCloseBtn")
        btn_close.setFixedSize(26, 26)
        btn_close.clicked.connect(self.close)

        header_layout.addWidget(btn_min, alignment=Qt.AlignmentFlag.AlignTop)
        header_layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignTop)
        main_layout.addLayout(header_layout)

        # --- FIRST SECTION: INPUT FIELDS ---
        # Source Folder
        main_layout.addWidget(self._make_section_label("Source Folder"))
        self.inp_source = SmartLineEdit("Select or drop and drop file or folder...", mode="source", parent_win=self)
        main_layout.addWidget(self.inp_source)

        # Extract To
        main_layout.addWidget(self._make_section_label("Extract To"))
        self.inp_extract = SmartLineEdit("Define extraction path...", mode="extract_to", parent_win=self)
        main_layout.addWidget(self.inp_extract)

        # Run File
        main_layout.addWidget(self._make_section_label("Run File"))
        self.inp_run = SmartLineEdit("Define run file path with parameters...", mode="run_file", parent_win=self)
        self.inp_run.textChanged.connect(self.on_run_file_changed)
        main_layout.addWidget(self.inp_run)

        # Output
        main_layout.addWidget(self._make_section_label("Output"))
        self.inp_output = SmartLineEdit("Define save path...", mode="output", parent_win=self)
        main_layout.addWidget(self.inp_output)

        # Name & Description
        main_layout.addWidget(self._make_section_label("Name & Description"))
        nd_layout = QHBoxLayout()
        nd_layout.setContentsMargins(0, 0, 0, 0)
        nd_layout.setSpacing(8)

        self.btn_icon = QPushButton()
        self.btn_icon.setObjectName("IconSelectBtn")
        self.btn_icon.setFixedSize(34, 34)
        # Uses the embedded SFX Icon.ico by default until another is chosen
        self.btn_icon.setIcon(self.default_gui_icon)
        self.btn_icon.setIconSize(QSize(24, 24))
        self.btn_icon.setToolTip("Click to choose icon options")
        self.btn_icon.clicked.connect(self.open_icon_menu)
        self.btn_icon.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.btn_icon.customContextMenuRequested.connect(self.reset_icon_to_default)
        self.btn_icon.setToolTip('Left-click: icon options. Right-click: restore the default icon.')
        nd_layout.addWidget(self.btn_icon)

        self.inp_name = QLineEdit()
        self.inp_name.setPlaceholderText("Name...")
        self.inp_name.setFixedHeight(34)
        self.inp_name.textEdited.connect(self.on_name_manually_edited)
        nd_layout.addWidget(self.inp_name, stretch=1)

        self.inp_desc = QLineEdit()
        self.inp_desc.setPlaceholderText("Description...")
        self.inp_desc.setFixedHeight(34)
        nd_layout.addWidget(self.inp_desc, stretch=1)

        main_layout.addLayout(nd_layout)

        # --- SECOND SECTION: OPTIONS (Wrapper_3.png Layout) ---
        main_layout.addWidget(self._make_section_label("Options"))
        opt_grid = QGridLayout()
        opt_grid.setContentsMargins(0, 2, 0, 4)
        opt_grid.setHorizontalSpacing(8)
        opt_grid.setVerticalSpacing(10)
        opt_grid.setColumnStretch(0, 1)
        opt_grid.setColumnStretch(1, 1)
        opt_grid.setColumnStretch(2, 1)

        # Row 0: Run As Admin | Hidden Run | Don't Replace
        self.chk_admin = QCheckBox("Run As Admin")
        self.chk_hidden = QCheckBox("Hidden Run")
        self.chk_dont_replace = QCheckBox("Don't Replace")

        # Row 1: Extract Only | Self Remove | Progress Bar
        self.chk_extract_only = QCheckBox("Extract Only")
        self.chk_extract_only.toggled.connect(self.on_extract_only_toggled)
        self.chk_hidden.toggled.connect(self.on_hidden_run_toggled)
        self.chk_self_remove = QCheckBox("Self Remove")
        self.chk_progress_bar = QCheckBox("Progress Bar")

        # Row 2: Compress | Crypto | Instances
        self.chk_compress = QCheckBox("Compress")
        self.chk_crypto = QCheckBox("Crypto")
        self.chk_instances = QCheckBox("Instances")

        all_checks = [
            self.chk_admin, self.chk_hidden, self.chk_dont_replace,
            self.chk_extract_only, self.chk_self_remove, self.chk_progress_bar,
            self.chk_compress, self.chk_crypto, self.chk_instances
        ]
        for chk in all_checks:
            chk.setFixedHeight(20)

        opt_grid.addWidget(self.chk_admin, 0, 0)
        opt_grid.addWidget(self.chk_hidden, 0, 1)
        opt_grid.addWidget(self.chk_dont_replace, 0, 2)

        opt_grid.addWidget(self.chk_extract_only, 1, 0)
        opt_grid.addWidget(self.chk_self_remove, 1, 1)
        opt_grid.addWidget(self.chk_progress_bar, 1, 2)

        opt_grid.addWidget(self.chk_compress, 2, 0)
        opt_grid.addWidget(self.chk_crypto, 2, 1)
        opt_grid.addWidget(self.chk_instances, 2, 2)

        main_layout.addLayout(opt_grid)

        # --- PROGRESS BAR ---
        main_layout.addSpacing(2)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(14)
        main_layout.addWidget(self.progress_bar)
        main_layout.addSpacing(4)

        # --- THIRD SECTION: EXPORT / IMPORT / PASSWORD / START PROCESS ---
        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(10)

        left_bottom = QVBoxLayout()
        left_bottom.setContentsMargins(0, 0, 0, 0)
        left_bottom.setSpacing(8)

        exp_imp_layout = QHBoxLayout()
        exp_imp_layout.setContentsMargins(0, 0, 0, 0)
        exp_imp_layout.setSpacing(8)
        self.btn_export = QPushButton("Export")
        self.btn_export.setObjectName("SmallBtn")
        self.btn_export.setFixedSize(58, 25)
        self.btn_export.clicked.connect(self.export_config)

        self.btn_import = QPushButton("Import")
        self.btn_import.setObjectName("SmallBtn")
        self.btn_import.setFixedSize(58, 25)
        self.btn_import.clicked.connect(self.import_config)

        exp_imp_layout.addWidget(self.btn_export)
        exp_imp_layout.addWidget(self.btn_import)
        left_bottom.addLayout(exp_imp_layout)

        # Password is optional: a non-empty field enables protection automatically.
        # Width matches the Export/Import row, filling the removed checkbox space.
        self.inp_password = QLineEdit()
        self.inp_password.setObjectName("PasswordInput")
        self.inp_password.setPlaceholderText("Password...")
        self.inp_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.inp_password.setFixedSize(124, 25)
        left_bottom.addWidget(self.inp_password)

        bottom_layout.addLayout(left_bottom)

        self.btn_start = QPushButton("Start Process")
        self.btn_start.setObjectName("StartBtn")
        self.btn_start.setFixedHeight(58)
        self.btn_start.clicked.connect(self.start_process)
        bottom_layout.addWidget(self.btn_start, stretch=1)

        main_layout.addLayout(bottom_layout)

        for field in (
            self.inp_source, self.inp_extract, self.inp_run, self.inp_output,
            self.inp_name, self.inp_desc, self.inp_password
        ):
            field.textChanged.connect(self.reset_start_status)
        for option in all_checks:
            option.toggled.connect(self.reset_start_status)
        self._refresh_hidden_availability()

    def reset_start_status(self, *args):
        self.btn_start.setText("Start Process")
        self.btn_start.setToolTip("")

    def _make_section_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("SectionLabel")
        lbl.setFixedHeight(18)
        return lbl

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #0b1016;
                color: #e2e8f0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
            }
            QLabel#HeaderTitle {
                font-size: 16px;
                font-weight: 600;
                color: #f1f5f9;
            }
            QLabel#HeaderSubtitle {
                font-size: 11px;
                color: #94a3b8;
            }
            QLabel#SectionLabel {
                font-size: 12px;
                font-weight: 600;
                color: #e2e8f0;
            }
            QPushButton#WinControlBtn, QPushButton#WinCloseBtn {
                background-color: transparent;
                border: none;
                color: #94a3b8;
                font-size: 13px;
            }
            QPushButton#WinControlBtn:hover {
                background-color: #1e293b;
                color: #ffffff;
            }
            QPushButton#WinCloseBtn:hover {
                background-color: #ef4444;
                color: #ffffff;
            }
            QLineEdit {
                background-color: #131b23;
                border: 1px solid #1e2936;
                border-radius: 4px;
                padding: 0px 10px;
                color: #e2e8f0;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 1px solid #3b82f6;
            }
            QLineEdit:disabled {
                background-color: #0d1218;
                color: #475569;
                border: 1px solid #151d26;
            }
            QLineEdit#PasswordInput {
                padding: 0px 8px;
                font-size: 11px;
            }
            QPushButton#IconSelectBtn {
                background-color: #131b23;
                border: 1px solid #1e2936;
                border-radius: 4px;
            }
            QPushButton#IconSelectBtn:hover {
                border: 1px solid #3b82f6;
            }
            QCheckBox {
                color: #64748b;
                spacing: 7px;
                font-size: 11px;
                font-weight: 500;
            }
            QCheckBox:checked {
                color: #e2e8f0;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                background-color: #131b23;
                border: 1px solid #1e2936;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background-color: #2563eb;
                border: 1px solid #3b82f6;
            }
            /* Alternative mode is muted, not disabled: click to switch. */
            QCheckBox[muted="true"] {
                color: #475569;
            }
            QCheckBox[muted="true"]::indicator {
                border: 1px solid #1a2430;
                background-color: #101721;
            }
            QCheckBox[muted="true"]:hover {
                color: #94a3b8;
            }
            QProgressBar {
                background-color: #26313f;
                border: none;
                border-radius: 1px;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
            }
            QPushButton#SmallBtn {
                background-color: #17202a;
                border: 1px solid #222f3d;
                border-radius: 3px;
                color: #64748b;
                font-size: 11px;
                padding: 0px 4px;
            }
            QPushButton#SmallBtn:hover {
                color: #cbd5e1;
                border-color: #334155;
            }
            QPushButton#StartBtn {
                background-color: #111820;
                border: 1px solid #1e2936;
                border-radius: 4px;
                color: #64748b;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton#StartBtn:hover {
                background-color: #17212c;
                color: #e2e8f0;
                border-color: #3b82f6;
            }
        """)

    # --- WINDOW DRAGGING ---
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and event.position().y() < 55:
            self.drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and not self.drag_pos.isNull():
            self.move(event.globalPosition().toPoint() - self.drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.drag_pos = QPoint()

    # --- HANDLERS & FEATURES ---
    def inspect_sfx_file(self, file_path: str):
        ok, result = process_file(os.path.normpath(file_path))
        if not ok:
            QMessageBox.information(self, 'SFX Code Viewer', result)

    def on_logo_clicked(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                'Select SFX / EXE File',
                '',
                'Executable Files (*.exe *.sfx);;All Files (*.*)'
            )
            if file_path:
                self.inspect_sfx_file(file_path)
            event.accept()


    def on_extract_only_toggled(self, checked: bool):
        # Exclusive, but never disable the other checkbox: clicking it switches modes.
        if checked and self.chk_hidden.isChecked():
            self.chk_hidden.setChecked(False)
        self.inp_run.setEnabled(not checked)
        self._refresh_hidden_availability()

    def on_hidden_run_toggled(self, checked: bool):
        if checked and self.chk_extract_only.isChecked():
            self.chk_extract_only.setChecked(False)
        self._refresh_hidden_availability()

    def _refresh_hidden_availability(self):
        """Slightly dim the opposite option, without disabling its mouse input."""
        extract_selected = self.chk_extract_only.isChecked()
        hidden_selected = self.chk_hidden.isChecked()

        # Both remain enabled even if the run script has not yet been specified.
        self.chk_hidden.setEnabled(True)
        self.chk_extract_only.setEnabled(True)

        self._style_mutually_exclusive_option(self.chk_hidden, extract_selected)
        self._style_mutually_exclusive_option(self.chk_extract_only, hidden_selected)
        self.chk_hidden.setToolTip(
            "Click to switch from Extract Only to Hidden Run. Supports BAT/CMD/PS1."
            if extract_selected else "Run BAT/CMD/PS1 using the embedded VBScript."
        )
        self.chk_extract_only.setToolTip(
            "Click to switch from Hidden Run to Extract Only."
            if hidden_selected else "Extract package contents without running a file."
        )

    @staticmethod
    def _style_mutually_exclusive_option(checkbox, dimmed: bool):
        if checkbox.property("muted") != dimmed:
            checkbox.setProperty("muted", dimmed)
            checkbox.style().unpolish(checkbox)
            checkbox.style().polish(checkbox)
            checkbox.update()

    def on_name_manually_edited(self, text: str):
        self._user_edited_name = bool(text.strip())

    def _extract_candidate_from_run_text(self, raw: str) -> str:
        raw = raw.strip()
        if not raw:
            return ''
        if raw.startswith('"'):
            end_q = raw.find('"', 1)
            return raw[1:end_q] if end_q > 1 else raw.strip('"')
        # A selected path can contain spaces without explicitly being quoted.
        match = re.match(r'^(.+?\.(?:bat|cmd|ps1|exe|reg))(?=\s|$)', raw, re.IGNORECASE)
        if match:
            return match.group(1)
        return raw.split()[0]

    def on_run_file_changed(self, text: str):
        """Automatically populates the Name field with the Run File's filename without extension."""
        self._refresh_hidden_availability()
        raw = text.strip()
        if not raw:
            if not self._user_edited_name:
                self.inp_name.setText("")
            return

        candidate = self._extract_candidate_from_run_text(raw)
        base_name = os.path.basename(candidate.replace("/", "\\"))
        stem, _ = os.path.splitext(base_name)
        if stem and not self._user_edited_name:
            self.inp_name.setText(stem)

    def reset_icon_to_default(self, _pos=None):
        """Restore the drawn default icon for GUI selection and built EXE."""
        self.current_icon_source = self.app_icon_path
        self.converted_ico_path = self.app_icon_path
        self.btn_icon.setIcon(self.default_gui_icon)
        self.btn_icon.setToolTip('Default Byte Wrapper icon restored. Left-click to select another.')
        self.reset_start_status()

    def open_icon_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #131b24;
                color: #e2e8f0;
                border: 1px solid #263445;
                padding: 4px;
                font-size: 12px;
            }
            QMenu::item {
                padding: 6px 18px;
                border-radius: 3px;
            }
            QMenu::item:selected {
                background-color: #2563eb;
                color: #ffffff;
            }
        """)
        act_auto = menu.addAction("1. Get Automatically from Run File")
        act_select = menu.addAction("2. Select Icon...")

        action = menu.exec(self.btn_icon.mapToGlobal(QPoint(0, self.btn_icon.height())))
        if action == act_auto:
            self.set_icon_from_run_file()
        elif action == act_select:
            self.select_icon_from_dialog()

    def _resolve_run_file_for_icon(self) -> str:
        raw_run = self.inp_run.text().strip()
        if not raw_run:
            return ""

        candidate = os.path.expandvars(self._extract_candidate_from_run_text(raw_run).replace("/", "\\"))
        if os.path.isfile(candidate):
            return candidate

        # Check inside Source Folder
        src = os.path.expandvars(self.inp_source.text().strip().replace("/", "\\"))
        if os.path.isfile(src):
            return src
        if os.path.isdir(src):
            direct = os.path.join(src, candidate)
            if os.path.isfile(direct):
                return direct
            fname = os.path.basename(candidate)
            if fname:
                for root_dir, _, files in os.walk(src):
                    for f in files:
                        if f.lower() == fname.lower():
                            return os.path.join(root_dir, f)

        # Check system PATH (e.g., cmd.exe, powershell.exe, regedit.exe)
        which_path = shutil.which(candidate) or shutil.which(os.path.basename(candidate))
        if which_path and os.path.isfile(which_path):
            return which_path

        return ""

    def set_icon_from_run_file(self):
        target_file = self._resolve_run_file_for_icon()
        if not target_file:
            self.btn_icon.setToolTip("Could not locate an icon from Run File or Source Folder.")
            return

        out_ico = os.path.join(tempfile.gettempdir(), "byte_wrapper_selected_icon.ico")
        if extract_icon_from_file(target_file, out_ico):
            self.current_icon_source = target_file
            self.converted_ico_path = out_ico
            self.btn_icon.setIcon(load_crisp_gui_icon(out_ico))
            self.reset_start_status()
        else:
            self.btn_icon.setToolTip(f"Could not extract icon from: {target_file}")

    def select_icon_from_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Icon or Application",
            "",
            "Icon & Executable Files (*.ico *.png *.jpeg *.jpg *.jxl *.exe)"
        )
        if not file_path:
            return

        ext = os.path.splitext(file_path)[1].lower()
        out_ico = os.path.join(tempfile.gettempdir(), "byte_wrapper_selected_icon.ico")

        if ext == ".exe":
            success = extract_icon_from_file(file_path, out_ico)
            if not success:
                self.btn_icon.setToolTip("Could not extract icon from the selected .exe file.")
                return
        else:
            success = convert_image_to_ico(file_path, out_ico)
            if not success:
                self.btn_icon.setToolTip("Could not convert the selected image to .ico format.")
                return

        self.current_icon_source = file_path
        self.converted_ico_path = out_ico
        self.btn_icon.setIcon(load_crisp_gui_icon(out_ico))
        self.reset_start_status()

    # --- PASSWORD BLINK ANIMATION (5 TIMES ON IMPORT) ---
    def trigger_password_blink(self):
        """Blinks the password text between plain text and hidden mode 5 times, then hides it."""
        self._blink_timer.stop()
        if not self.inp_password.text():
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Password)
            return
        self._blink_step_count = 0
        self.inp_password.setEchoMode(QLineEdit.EchoMode.Normal)
        self._blink_timer.start(180)

    def _on_blink_step(self):
        self._blink_step_count += 1
        # 5 full blinks = 10 transitions (Normal -> Password -> Normal ... -> Password)
        if self._blink_step_count >= 10:
            self._blink_timer.stop()
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Password)
            return

        if self._blink_step_count % 2 == 1:
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Password)
        else:
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Normal)

    def collect_config(self) -> dict:
        return {
            "source": self.inp_source.text(),
            "extract_to": self.inp_extract.text(),
            "run_file": self.inp_run.text(),
            "output": self.inp_output.text(),
            "name": self.inp_name.text(),
            "description": self.inp_desc.text(),
            "icon_source": self.current_icon_source,
            "icon_ico": self.converted_ico_path,
            "run_as_admin": self.chk_admin.isChecked(),
            "hidden_run": self.chk_hidden.isChecked(),
            "dont_replace": self.chk_dont_replace.isChecked(),
            "extract_only": self.chk_extract_only.isChecked(),
            "self_remove": self.chk_self_remove.isChecked(),
            "progress_bar": self.chk_progress_bar.isChecked(),
            "compress": self.chk_compress.isChecked(),
            "crypto": self.chk_crypto.isChecked(),
            "instances": self.chk_instances.isChecked(),
            "use_password": bool(self.inp_password.text().strip()),
            "password": self.inp_password.text(),
        }

    def export_config(self):
        cfg = self.collect_config()
        # Encrypt the password field before saving to JSON
        export_data = dict(cfg)
        export_data.pop("icon_ico", None)
        export_data["password"] = encrypt_password_for_export(cfg.get("password", ""))

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Configuration Script", "byte_wrapper_config.json", "JSON Script (*.json)"
        )
        if not save_path:
            return
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            self.btn_export.setToolTip(f"Failed to export configuration: {e}")

    def import_config(self):
        open_path, _ = QFileDialog.getOpenFileName(
            self, "Import Configuration Script", "", "JSON Script (*.json)"
        )
        if not open_path:
            return
        try:
            with open(open_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)

            self._user_edited_name = bool(cfg.get("name", "").strip())
            self.inp_source.setText(cfg.get("source", ""))
            self.inp_extract.setText(cfg.get("extract_to", ""))
            self.inp_run.setText(cfg.get("run_file", ""))
            self.inp_output.setText(cfg.get("output", ""))
            self.inp_name.setText(cfg.get("name", ""))
            self.inp_desc.setText(cfg.get("description", ""))

            self.chk_admin.setChecked(cfg.get("run_as_admin", False))
            self.chk_hidden.setChecked(cfg.get("hidden_run", False))
            self.chk_dont_replace.setChecked(cfg.get("dont_replace", False))
            self.chk_extract_only.setChecked(cfg.get("extract_only", False))
            self.chk_self_remove.setChecked(cfg.get("self_remove", False))
            self.chk_progress_bar.setChecked(cfg.get("progress_bar", False))
            self.chk_compress.setChecked(cfg.get("compress", False))
            self.chk_crypto.setChecked(cfg.get("crypto", False))
            self.chk_instances.setChecked(cfg.get("instances", False))
            self._refresh_hidden_availability()

            decrypted_pw = decrypt_password_from_import(cfg.get("password", ""))
            self.inp_password.setText(decrypted_pw)
            if decrypted_pw:
                self.trigger_password_blink()

            icon_src = cfg.get("icon_source", "")
            if icon_src and os.path.exists(icon_src):
                out_ico = os.path.join(tempfile.gettempdir(), "byte_wrapper_selected_icon.ico")
                if icon_src.lower().endswith(".exe"):
                    extract_icon_from_file(icon_src, out_ico)
                else:
                    convert_image_to_ico(icon_src, out_ico)
                if os.path.exists(out_ico):
                    self.current_icon_source = icon_src
                    self.converted_ico_path = out_ico
                    self.btn_icon.setIcon(load_crisp_gui_icon(out_ico))
            else:
                self.current_icon_source = self.app_icon_path
                self.converted_ico_path = self.app_icon_path
                self.btn_icon.setIcon(self.default_gui_icon)

        except Exception as e:
            self.btn_import.setToolTip(f"Failed to import configuration: {e}")

    def start_process(self):
        cfg = self.collect_config()
        if not cfg["source"].strip():
            self.btn_start.setToolTip("Please specify a Source Folder or file.")
            return
        if not cfg["output"].strip():
            self.btn_start.setToolTip("Please specify an Output save directory.")
            return

        self.btn_start.setEnabled(False)
        self.progress_bar.setValue(0)

        self.worker = SFXBuilderWorker(cfg)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_process_finished)
        self.worker.start()

    def on_process_finished(self, success: bool, message: str):
        self.btn_start.setEnabled(True)
        if success:
            self.btn_start.setText("Completed")
            self.btn_start.setToolTip(message)
        else:
            self.progress_bar.setValue(0)
            self.btn_start.setText("Failed")
            self.btn_start.setToolTip(message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ByteWrapperWindow()
    win.show()
    sys.exit(app.exec())