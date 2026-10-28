import os
import re
import sys
import glob
import json
import uuid
import errno
import struct
import base64
import hashlib
import shutil
import ctypes
from ctypes import wintypes
import subprocess
import tempfile
import threading
import time
import mmap
import io
from collections import deque
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

# Support #
# Update Python # py -m pip install --upgrade pip
# Install Components # py -m pip install PyQt6 Pillow pillow-jxl-plugin pywin32 pyinstaller
# Check Components # py -c "from PyQt6.QtWidgets import QApplication; from PIL import Image; import pillow_jxl, win32ui, win32gui, win32con; print('All dependencies OK')"
# Compile # py -m PyInstaller --noconfirm --clean --onefile --windowed --name "Byte Wrapper" --icon "Byte.ICO" --collect-all pillow_jxl --hidden-import win32ui --hidden-import win32gui --hidden-import win32con "Byte Wrapper.py"

# Hide the console window immediately when launched via python.exe on Windows
if os.name == "nt":
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE = 0
        # Ensure Windows Taskbar displays our custom icon instead of python.exe icon
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ByteWrapper.SFXConstructor")
    except Exception:
        pass


# Show unexpected startup errors without creating an error log file.
def _show_uncaught_error(exc_type, exc_value, exc_tb):
    sys.__excepthook__(exc_type, exc_value, exc_tb)
    if os.name == "nt":
        try:
            ctypes.windll.user32.MessageBoxW(
                None,
                "Byte Wrapper encountered an error:\n\n" + str(exc_value),
                "Byte Wrapper Error", 0x10,
            )
        except Exception:
            pass


sys.excepthook = _show_uncaught_error


from PyQt6.QtCore import (
    Qt, QPoint, QThread, pyqtSignal, QSize, QTimer, QUrl, QRegularExpression
)
from PyQt6.QtGui import (
    QIcon, QPixmap, QDragEnterEvent, QDropEvent,
    QDesktopServices, QRegularExpressionValidator
)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QProgressBar,
    QFileDialog, QMenu, QMessageBox
)

from PIL import Image, ImageDraw, ImageFilter
try:
    import pillow_jxl  # Support for .jxl files
except ImportError:
    pass


# ==========================================
# WINDOWS API BINDINGS & VALIDATION HELPERS
# ==========================================
if os.name == "nt":
    _win32_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _win32_k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _win32_k32.OpenProcess.restype = wintypes.HANDLE

    _win32_k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _win32_k32.GetExitCodeProcess.restype = wintypes.BOOL

    _win32_k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _win32_k32.CreateFileW.restype = wintypes.HANDLE

    _win32_k32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _win32_k32.MoveFileExW.restype = wintypes.BOOL

    _win32_k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _win32_k32.CloseHandle.restype = wintypes.BOOL

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
else:
    _win32_k32 = None
    _INVALID_HANDLE_VALUE = -1


WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
    "COM\u00b9", "COM\u00b2", "COM\u00b3",
    "LPT\u00b9", "LPT\u00b2", "LPT\u00b3",
}

_ILLEGAL_PATH_CHARS_RE = re.compile(r'[<>"|?*]')
_BW_SOURCE_START_MARKER = b";!@ByteWrapperSource@UTF-8!"
_BW_SOURCE_END_MARKER = b";!@ByteWrapperSourceEnd@!"
_BW_HEADER_SCAN_LIMIT = 12 * 1024 * 1024  # Embedded C# source always precedes payload overlay (<12 MB)


def _is_unc_or_drive_abs(raw_path: str) -> bool:
    """Return True if raw_path (after env expansion) is a UNC path (\\\\server\\share) or drive-rooted path."""
    if not raw_path:
        return False
    cleaned = raw_path.strip()
    while len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
        cleaned = cleaned[1:-1].strip()
    if not cleaned:
        return False
    expanded = os.path.expanduser(os.path.expandvars(cleaned)).replace("/", "\\")
    if expanded.startswith("\\\\"):
        return True
    if len(expanded) >= 2 and expanded[0].isalpha() and expanded[1] == ":":
        return True
    return False


def _strip_relative_leading_slashes(path_str: str) -> str:
    """Strip single leading slashes from a relative path while preserving UNC '\\\\server\\share' paths."""
    if not path_str:
        return ""
    if _is_unc_or_drive_abs(path_str):
        return normalize_user_path(path_str)
    normed = normalize_user_path(path_str).replace("/", "\\")
    if normed.startswith("\\\\"):
        return normed
    return normed.lstrip("\\")


def normalize_user_path(raw_path: str) -> str:
    """Strip quotes/spaces, expand environment and user variables, and normalize path separators."""
    if not raw_path:
        return ""
    cleaned = raw_path.strip()
    while len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
        cleaned = cleaned[1:-1].strip()
    if not cleaned:
        return ""
    expanded = os.path.expanduser(os.path.expandvars(cleaned))
    normed = os.path.normpath(expanded)
    # Preserve UNC double backslash if input was a UNC path
    if expanded.replace("/", "\\").startswith("\\\\") and not normed.startswith("\\\\"):
        normed = "\\" + normed.lstrip("\\")
    return normed


def paths_refer_to_same_location(path_a: str, path_b: str) -> bool:
    """Return True if two paths resolve to the exact same file or directory on disk."""
    norm_a = normalize_user_path(path_a)
    norm_b = normalize_user_path(path_b)
    if not norm_a or not norm_b:
        return False
    try:
        if os.path.exists(norm_a) and os.path.exists(norm_b):
            return os.path.samefile(norm_a, norm_b)
    except OSError:
        pass
    real_a = os.path.normcase(os.path.realpath(os.path.abspath(norm_a)))
    real_b = os.path.normcase(os.path.realpath(os.path.abspath(norm_b)))
    return real_a == real_b


def is_windows_reserved_name(name: str) -> bool:
    """Return True if a file or folder name matches a Windows reserved device name (including CON.foo.bar)."""
    if not name:
        return False
    cleaned = name.strip().rstrip(". ")
    if not cleaned:
        return False
    stem = cleaned.split(".", 1)[0].strip().rstrip(". ").upper()
    return stem in WINDOWS_RESERVED_NAMES


def path_has_reserved_or_invalid_component(raw_path: str) -> bool:
    """Return True if a path contains illegal characters or any reserved Windows device segment."""
    if not raw_path:
        return False
    expanded = normalize_user_path(raw_path).replace("/", "\\")
    _, tail = os.path.splitdrive(expanded)
    if _ILLEGAL_PATH_CHARS_RE.search(tail) or ":" in tail:
        return True
    for part in tail.split("\\"):
        part_clean = part.strip()
        if not part_clean or part_clean in (".", ".."):
            continue
        if is_windows_reserved_name(part_clean):
            return True
    return False


def is_valid_output_directory_path(raw_path: str) -> bool:
    """Verify output path syntax, drive existence, and ensure it does not point to an existing file."""
    norm_out = normalize_user_path(raw_path)
    if not norm_out or path_has_reserved_or_invalid_component(norm_out):
        return False
    if os.path.isfile(norm_out):
        return False
    drive, _ = os.path.splitdrive(norm_out)
    if drive and not drive.startswith("\\\\"):
        drive_root = drive + "\\"
        if not os.path.exists(drive_root):
            return False
    return True


def is_valid_version_string(raw_ver: str) -> bool:
    """Validate version string using strict ASCII digits so values like 'abc123' or '1.²' are rejected."""
    cleaned = (raw_ver or "").strip()
    if not cleaned:
        return True
    parts = cleaned.split(".")
    if not (1 <= len(parts) <= 4):
        return False
    for part in parts:
        if len(part) > 5 or not re.fullmatch(r"[0-9]+", part):
            return False
        val = int(part)
        if not (0 <= val <= 65534):
            return False
    return True


def _normalize_pe_version(raw_ver: str) -> tuple[str, str]:
    """Return (numeric_4_part_version, informational_version) for C# Assembly attributes."""
    cleaned = (raw_ver or "").strip()
    if not cleaned or not is_valid_version_string(cleaned):
        return "1.0.0.0", "1.0.0.0"
    nums = [int(p) for p in cleaned.split(".")[:4]]
    while len(nums) < 4:
        nums.append(0)
    clamped = [str(min(65534, max(0, x))) for x in nums]
    return ".".join(clamped), cleaned


def _is_byte_wrapper_sfx_file(file_path: str) -> bool:
    """Fast check for Byte Wrapper SFX signature within the initial stub header (<12 MB)."""
    try:
        if not file_path or not os.path.isfile(file_path):
            return False
        size = os.path.getsize(file_path)
        if size < 64:
            return False
        scan_len = min(size, _BW_HEADER_SCAN_LIMIT)
        with open(file_path, "rb") as f, mmap.mmap(f.fileno(), scan_len, access=mmap.ACCESS_READ) as data:
            start_idx = data.find(_BW_SOURCE_START_MARKER)
            if start_idx < 0:
                return False
            end_idx = data.find(_BW_SOURCE_END_MARKER, start_idx + len(_BW_SOURCE_START_MARKER))
            return end_idx > start_idx
    except Exception:
        return False


def _is_pid_running(pid: int) -> bool:
    """Return True if a process with the given PID is currently active."""
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt" and _win32_k32 is not None:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        ERROR_ACCESS_DENIED = 5

        ctypes.set_last_error(0)
        handle = _win32_k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle or handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            return err == ERROR_ACCESS_DENIED
        try:
            exit_code = wintypes.DWORD(0)
            if _win32_k32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return exit_code.value == STILL_ACTIVE
            return True
        finally:
            _win32_k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def _is_file_in_use(file_path: str) -> bool:
    """Check if a file is currently open by any process on Windows using exclusive sharing."""
    if not file_path or not os.path.isfile(file_path):
        return False
    if os.name == "nt" and _win32_k32 is not None:
        GENERIC_READ = 0x80000000
        FILE_SHARE_NONE = 0x00000000
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x80
        ERROR_FILE_NOT_FOUND = 2
        ERROR_PATH_NOT_FOUND = 3

        ctypes.set_last_error(0)
        handle = _win32_k32.CreateFileW(
            file_path,
            GENERIC_READ,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if not handle or handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            if err in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND):
                return False
            return True
        _win32_k32.CloseHandle(handle)
        return False
    return False


def cleanup_stale_temp_files(max_age_seconds: int = 3600, protected_paths: set[str] | None = None):
    """Remove old preview text files and stale session icons only if they are not in use."""
    temp_dir = tempfile.gettempdir()
    now = time.time()
    current_pid = os.getpid()

    protected_norm = set()
    if protected_paths:
        for p in protected_paths:
            if p:
                protected_norm.add(os.path.normcase(os.path.abspath(p)))

    # 1. Clean old preview text files that are not open/in-use
    for path in glob.glob(os.path.join(temp_dir, "byte_wrapper_code_*.txt")):
        try:
            norm_p = os.path.normcase(os.path.abspath(path))
            if norm_p in protected_norm:
                continue
            last_touch = max(os.path.getmtime(path), os.path.getatime(path))
            if now - last_touch > max_age_seconds and not _is_file_in_use(path):
                os.unlink(path)
        except OSError:
            pass

    # 2. Clean session icon files only if their owning PID is no longer running and file is not in use
    icon_pid_re = re.compile(r"^byte_wrapper_selected_icon_(\d+)(?:_[0-9a-f]+)?\.ico$", re.IGNORECASE)
    for path in glob.glob(os.path.join(temp_dir, "byte_wrapper_selected_icon_*.ico")):
        try:
            norm_p = os.path.normcase(os.path.abspath(path))
            if norm_p in protected_norm:
                continue
            fname = os.path.basename(path)
            m = icon_pid_re.match(fname)
            if m:
                owner_pid = int(m.group(1))
                if owner_pid == current_pid or _is_pid_running(owner_pid):
                    continue
            elif now - os.path.getmtime(path) <= max_age_seconds:
                continue

            if not _is_file_in_use(path):
                os.unlink(path)
        except OSError:
            pass


def open_with_default_viewer(file_path: str) -> bool:
    """Open a file or folder with the operating system's default handler (no notepad dependency)."""
    norm_path = os.path.normpath(file_path)
    if hasattr(os, "startfile"):
        try:
            os.startfile(norm_path)
            return True
        except OSError:
            pass
    return QDesktopServices.openUrl(QUrl.fromLocalFile(norm_path))


# ==========================================
# SFX CONFIG READER
# ==========================================
def process_file(file_path):
    """Open real 7-Zip SFX configs or Byte Wrapper's embedded C# source in the default viewer.

    This is inspection only: changes saved in the editor do not change the EXE.
    The file itself is never executed.
    Returns a (success, explanation) tuple for the GUI.
    """
    cleanup_stale_temp_files()
    sources = (
        (b';!@Install@!UTF-8!', b';!@InstallEnd@!', '7-Zip SFX config'),
        (b';!@Install@!', b';!@InstallEnd@!', '7-Zip SFX config'),
        (_BW_SOURCE_START_MARKER, _BW_SOURCE_END_MARKER,
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

        if not open_with_default_viewer(output_file):
            return False, 'Unable to open the default text viewer for the extracted configuration.'
        return True, output_file
    except Exception as exc:
        return False, f'Unable to open SFX code: {exc}'


# ==========================================
# PASSWORD ENCRYPTION FOR EXPORT / IMPORT
# ==========================================
SECRET_EXPORT_KEY = b"ByteWrapper_Config_Cipher_Key"


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
# HIGH-DEFINITION ICON UTILITIES
# ==========================================
def save_crisp_multi_ico(master_img: Image.Image, out_ico_path: str,
                         sizes=(256, 128, 64, 48, 32, 24, 16)) -> bool:
    """Build a multi-resolution Windows ICO with LANCZOS resampling per layer."""
    try:
        src = master_img.convert("RGBA")
        if src.width != src.height:
            side = max(src.width, src.height)
            square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
            square.paste(src, ((side - src.width) // 2, (side - src.height) // 2))
            src = square

        entries = []
        payloads = []

        for sz in sizes:
            layer = src.resize((sz, sz), Image.Resampling.LANCZOS)
            if sz <= 48:
                layer = layer.filter(ImageFilter.UnsharpMask(radius=0.7, percent=55, threshold=2))

            if sz >= 256:
                buf = io.BytesIO()
                layer.save(buf, format="PNG", optimize=True)
                raw_data = buf.getvalue()
            else:
                flipped = layer.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
                xor_mask = flipped.tobytes("raw", "BGRA")
                and_row_bytes = ((sz + 31) // 32) * 4
                and_mask = b"\x00" * (and_row_bytes * sz)
                bmp_header = struct.pack(
                    "<IIIHHIIIIII",
                    40,
                    sz,
                    sz * 2,
                    1,
                    32,
                    0,
                    len(xor_mask) + len(and_mask),
                    0, 0, 0, 0
                )
                raw_data = bmp_header + xor_mask + and_mask

            w_byte = 0 if sz >= 256 else sz
            h_byte = 0 if sz >= 256 else sz
            entries.append((w_byte, h_byte, 0, 0, 1, 32, len(raw_data)))
            payloads.append(raw_data)

        header = struct.pack("<HHH", 0, 1, len(entries))
        offset = 6 + 16 * len(entries)
        dir_bytes = bytearray()
        for w_b, h_b, col, res, planes, bpp, length in entries:
            dir_bytes.extend(struct.pack("<BBBBHHII", w_b, h_b, col, res, planes, bpp, length, offset))
            offset += length

        with open(out_ico_path, "wb") as f:
            f.write(header)
            f.write(dir_bytes)
            for chunk in payloads:
                f.write(chunk)
        return True
    except Exception:
        return False


def _render_parcel_canvas(canvas: int = 1024, stroke_scale: float = 1.0) -> Image.Image:
    """Render the clean vector parcel icon onto an RGBA canvas."""
    factor = canvas / 214.0
    img = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    ink = "#383838"
    face = "#ffffff"

    def xy(x, y):
        return (round(x * factor), round(y * factor))

    def poly(points, fill):
        draw.polygon([xy(*point) for point in points], fill=fill)

    def stroke(points, width=6.5):
        w = max(1, round(width * stroke_scale * factor))
        coords = [xy(*point) for point in points]
        draw.line(coords, fill=ink, width=w, joint="curve")
        r = w / 2.0
        for cx, cy in (coords[0], coords[-1]):
            draw.ellipse((round(cx - r), round(cy - r), round(cx + r), round(cy + r)), fill=ink)

    poly([(12, 53), (105, 15), (198, 53), (106, 96)], face)   # top
    poly([(12, 53), (106, 96), (106, 205), (12, 162)], face)  # left
    poly([(106, 96), (198, 53), (198, 162), (106, 205)], face)  # right

    stroke([(12, 53), (105, 15), (198, 53), (198, 162),
            (106, 205), (12, 162), (12, 53)], width=6.8)
    stroke([(12, 53), (106, 96), (198, 53)], width=6.8)
    stroke([(106, 96), (106, 205)], width=6.8)

    stroke([(43, 40), (138, 80)], width=6.0)
    stroke([(76, 27), (166, 68)], width=6.0)
    stroke([(139, 80), (139, 120), (166, 110), (166, 68)], width=6.2)
    return img


def draw_default_sfx_icon(out_ico_path: str) -> None:
    """Render the parcel icon as a sharp multi-size Windows ICO."""
    img = _render_parcel_canvas(1024, stroke_scale=1.08)
    save_crisp_multi_ico(img, out_ico_path)


def get_app_icon_path() -> str:
    """Return a reusable, drawn default ICO without unpacking embedded data."""
    icon_path = os.path.join(tempfile.gettempdir(), "byte_wrapper_vector_box.ico")
    if os.path.isfile(icon_path) and os.path.getsize(icon_path) > 4096:
        return icon_path
    try:
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
        print("Unable to create drawn icon:", exc, file=sys.stderr)
        return ""


def create_unique_temp_icon_path() -> str:
    """Return a unique temporary ICO path per icon selection tied to the current PID."""
    unique_id = uuid.uuid4().hex[:8]
    return os.path.join(tempfile.gettempdir(), f"byte_wrapper_selected_icon_{os.getpid()}_{unique_id}.ico")


def load_best_pil_from_ico(ico_path: str) -> Image.Image | None:
    """Extract the highest-resolution 32-bit RGBA layer from any .ico file."""
    if not ico_path or not os.path.isfile(ico_path):
        return None
    try:
        with open(ico_path, "rb") as f:
            data = f.read()
        if len(data) >= 6:
            reserved, ico_type, count = struct.unpack_from("<HHH", data, 0)
            if reserved == 0 and ico_type == 1 and count > 0:
                candidates = []
                for i in range(count):
                    pos = 6 + i * 16
                    if pos + 16 > len(data):
                        break
                    w, h, col, rsv, planes, bpp, size, offset = struct.unpack_from("<BBBBHHII", data, pos)
                    real_w = 256 if w == 0 else w
                    real_h = 256 if h == 0 else h
                    if offset + size <= len(data) and size > 0:
                        candidates.append((real_w * real_h, bpp, i, offset, size, data[offset:offset + size]))

                candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
                for _, _, idx, offset, size, chunk in candidates:
                    if chunk.startswith(b"\x89PNG\r\n\x1a\n"):
                        with Image.open(io.BytesIO(chunk)) as png_img:
                            return png_img.convert("RGBA")
                    pos = 6 + idx * 16
                    single_dir = bytearray(data[pos:pos + 16])
                    struct.pack_into("<I", single_dir, 12, 22)
                    single_ico = struct.pack("<HHH", 0, 1, 1) + bytes(single_dir) + chunk
                    try:
                        with Image.open(io.BytesIO(single_ico)) as sub_img:
                            return sub_img.convert("RGBA")
                    except Exception:
                        continue
    except Exception:
        pass

    try:
        with Image.open(ico_path) as source:
            if source.format == "ICO" and hasattr(source, "ico"):
                sizes = source.ico.sizes()
                largest = max(sizes, key=lambda pair: pair[0] * pair[1])
                return source.ico.getimage(largest).convert("RGBA")
            return source.convert("RGBA")
    except Exception:
        return None


def pil_to_qpixmap(pil_img: Image.Image, logical_size: int, dpr: float = 1.0) -> QPixmap:
    """Render a PIL image at the exact physical pixel size (logical_size * dpr) using LANCZOS."""
    target_px = max(1, round(logical_size * dpr))
    if pil_img.width != target_px or pil_img.height != target_px:
        resampled = pil_img.resize((target_px, target_px), Image.Resampling.LANCZOS)
        if target_px <= 48:
            resampled = resampled.filter(ImageFilter.UnsharpMask(radius=0.6, percent=45, threshold=2))
    else:
        resampled = pil_img

    stream = io.BytesIO()
    resampled.save(stream, format="PNG")
    pixmap = QPixmap()
    pixmap.loadFromData(stream.getvalue(), "PNG")
    pixmap.setDevicePixelRatio(dpr)
    return pixmap


def load_crisp_gui_icon(ico_path: str, dpr: float = 1.0) -> QIcon:
    """Build a multi-size LANCZOS-resampled QIcon so Qt never performs blurry scaling."""
    pil_img = load_best_pil_from_ico(ico_path)
    if pil_img is None:
        return QIcon(ico_path) if ico_path else QIcon()

    icon = QIcon()
    for sz in (16, 20, 24, 28, 32, 36, 40, 48, 64, 96, 128, 256):
        pix_1x = pil_to_qpixmap(pil_img, sz, 1.0)
        if not pix_1x.isNull():
            icon.addPixmap(pix_1x)
        if dpr > 1.0:
            pix_hi = pil_to_qpixmap(pil_img, sz, dpr)
            if not pix_hi.isNull():
                icon.addPixmap(pix_hi)
    return icon


def _extract_pe_icon_bytes(pe_path: str, icon_index: int = 0) -> bytes:
    """Extract raw, untouched RT_GROUP_ICON + RT_ICON bytes directly from a PE (.exe/.dll/.mun) file."""
    if os.name != "nt" or not pe_path or not os.path.isfile(pe_path):
        return b""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    kernel32.LoadLibraryExW.restype = ctypes.c_void_p
    kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
    kernel32.FreeLibrary.restype = ctypes.c_int
    kernel32.FindResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    kernel32.FindResourceW.restype = ctypes.c_void_p
    kernel32.LoadResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.LoadResource.restype = ctypes.c_void_p
    kernel32.LockResource.argtypes = [ctypes.c_void_p]
    kernel32.LockResource.restype = ctypes.c_void_p
    kernel32.SizeofResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.SizeofResource.restype = ctypes.c_uint32

    LOAD_LIBRARY_AS_DATAFILE = 0x00000002
    LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020
    RT_ICON = 3
    RT_GROUP_ICON = 14

    hmod = kernel32.LoadLibraryExW(
        pe_path, None, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE
    )
    if not hmod:
        return b""

    try:
        group_ids = []
        ENUMRESNAMEPROCW = ctypes.WINFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t
        )
        kernel32.EnumResourceNamesW.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ENUMRESNAMEPROCW, ctypes.c_ssize_t
        ]
        kernel32.EnumResourceNamesW.restype = ctypes.c_int

        def _enum_cb(_hModule, _lpszType, lpszName, _lParam):
            if not lpszName:
                return 1
            if lpszName < 0x10000:
                group_ids.append(int(lpszName))
            else:
                group_ids.append(ctypes.wstring_at(lpszName))
            return 1

        cb_func = ENUMRESNAMEPROCW(_enum_cb)
        kernel32.EnumResourceNamesW(hmod, ctypes.c_void_p(RT_GROUP_ICON), cb_func, 0)

        if not group_ids:
            return b""

        target_id = None
        if icon_index < 0:
            abs_id = abs(icon_index)
            if abs_id in group_ids:
                target_id = abs_id
            elif str(abs_id) in group_ids:
                target_id = str(abs_id)
        if target_id is None:
            idx = icon_index if 0 <= icon_index < len(group_ids) else 0
            target_id = group_ids[idx]

        def _find_and_read(res_type: int, res_id) -> bytes:
            str_buf = None
            if isinstance(res_id, int):
                name_ptr = ctypes.c_void_p(res_id)
            else:
                str_buf = ctypes.c_wchar_p(res_id)
                name_ptr = ctypes.cast(str_buf, ctypes.c_void_p)
            hres = kernel32.FindResourceW(hmod, name_ptr, ctypes.c_void_p(res_type))
            if not hres:
                return b""
            size = kernel32.SizeofResource(hmod, hres)
            if size == 0:
                return b""
            hglob = kernel32.LoadResource(hmod, hres)
            if not hglob:
                return b""
            ptr = kernel32.LockResource(hglob)
            if not ptr:
                return b""
            return ctypes.string_at(ptr, size)

        grp_data = _find_and_read(RT_GROUP_ICON, target_id)
        if len(grp_data) < 6:
            return b""

        reserved, res_type_hdr, count = struct.unpack_from("<HHH", grp_data, 0)
        if reserved != 0 or res_type_hdr != 1 or count == 0:
            return b""

        valid_layers = []
        for i in range(count):
            pos = 6 + i * 14
            if pos + 14 > len(grp_data):
                break
            entry_12 = grp_data[pos:pos + 12]
            n_id, = struct.unpack_from("<H", grp_data, pos + 12)
            icon_chunk = _find_and_read(RT_ICON, n_id)
            if icon_chunk:
                valid_layers.append((entry_12, icon_chunk))

        if not valid_layers:
            return b""

        out_header = struct.pack("<HHH", 0, 1, len(valid_layers))
        offset = 6 + 16 * len(valid_layers)
        out_dir = bytearray()
        out_payloads = bytearray()

        for entry_12, chunk in valid_layers:
            fixed_12 = entry_12[:8] + struct.pack("<I", len(chunk))
            out_dir.extend(fixed_12)
            out_dir.extend(struct.pack("<I", offset))
            out_payloads.extend(chunk)
            offset += len(chunk)

        return out_header + bytes(out_dir) + bytes(out_payloads)
    finally:
        kernel32.FreeLibrary(hmod)


def _resolve_associated_icon_source(file_path: str) -> tuple[str, int]:
    """Find the system binary and icon index associated with a script or file extension."""
    ext = os.path.splitext(file_path)[1].lower()
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(sys_root, "System32")

    known_map = {
        ".ps1": (os.path.join(sys32, r"WindowsPowerShell\v1.0\powershell.exe"), 0),
        ".reg": (os.path.join(sys_root, "regedit.exe"), 0),
        ".msi": (os.path.join(sys32, "msiexec.exe"), 0),
        ".bat": (os.path.join(sys32, "imageres.dll"), -68),
        ".cmd": (os.path.join(sys32, "imageres.dll"), -68),
    }
    if ext in known_map:
        bin_path, idx = known_map[ext]
        if os.path.isfile(bin_path):
            return bin_path, idx

    try:
        ASSOCSTR_DEFAULTICON = 15
        buf = ctypes.create_unicode_buffer(512)
        cch = ctypes.c_uint32(512)
        hr = ctypes.windll.shlwapi.AssocQueryStringW(
            0, ASSOCSTR_DEFAULTICON, ctypes.c_wchar_p(ext), None, buf, ctypes.byref(cch)
        )
        if hr == 0 and buf.value:
            raw_val = os.path.expandvars(buf.value.strip())
            idx = 0
            if "," in raw_val:
                path_part, idx_part = raw_val.rsplit(",", 1)
                raw_val = path_part.strip().strip('"')
                try:
                    idx = int(idx_part.strip())
                except ValueError:
                    idx = 0
            else:
                raw_val = raw_val.strip('"')
            if os.path.isfile(raw_val):
                return raw_val, idx
    except Exception:
        pass

    return file_path, 0


def extract_icon_from_file(file_path: str, out_ico_path: str) -> bool:
    """Extract a lossless, high-resolution multi-size .ico from an .exe, DLL, or script."""
    if not file_path or not os.path.isfile(file_path):
        return False

    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".ico":
        try:
            shutil.copy2(file_path, out_ico_path)
            return True
        except OSError:
            return False

    target_bin, icon_idx = _resolve_associated_icon_source(file_path)

    candidates_to_try = [target_bin]
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    mun_candidate = os.path.join(sys_root, "SystemResources", os.path.basename(target_bin) + ".mun")
    if os.path.isfile(mun_candidate):
        candidates_to_try.append(mun_candidate)

    for candidate in candidates_to_try:
        ico_bytes = _extract_pe_icon_bytes(candidate, icon_idx)
        if ico_bytes:
            try:
                with open(out_ico_path, "wb") as f:
                    f.write(ico_bytes)
                best_pil = load_best_pil_from_ico(out_ico_path)
                if best_pil is not None and best_pil.width >= 48:
                    return True
            except OSError:
                pass

    try:
        import win32ui
        import win32gui
        import win32con

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)

        user32.PrivateExtractIconsW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint),
            ctypes.c_uint, ctypes.c_uint,
        ]
        user32.PrivateExtractIconsW.restype = ctypes.c_uint

        user32.DestroyIcon.argtypes = [ctypes.c_void_p]
        user32.DestroyIcon.restype = wintypes.BOOL

        shell32.ExtractAssociatedIconW.argtypes = [
            wintypes.HINSTANCE, wintypes.LPWSTR, ctypes.POINTER(wintypes.WORD)
        ]
        shell32.ExtractAssociatedIconW.restype = ctypes.c_void_p

        hicon = 0
        for candidate in candidates_to_try:
            phicon = (ctypes.c_void_p * 1)()
            piconid = (ctypes.c_uint * 1)()
            count = user32.PrivateExtractIconsW(
                candidate, icon_idx, 256, 256,
                phicon, piconid, 1, 0
            )
            if count > 0 and phicon[0]:
                hicon = phicon[0]
                break

        if not hicon:
            buf = ctypes.create_unicode_buffer(file_path, 260)
            pi_icon = wintypes.WORD(0)
            hicon = shell32.ExtractAssociatedIconW(None, buf, ctypes.byref(pi_icon))

        if not hicon:
            return False

        size = 256
        screen_dc = win32gui.GetDC(0)
        hdc_screen = win32ui.CreateDCFromHandle(screen_dc)
        hdc_mem = hdc_screen.CreateCompatibleDC()
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc_screen, size, size)
        old_bmp = hdc_mem.SelectObject(hbmp)

        try:
            win32gui.DrawIconEx(
                hdc_mem.GetSafeHdc(), 0, 0, hicon,
                size, size, 0, None, win32con.DI_NORMAL
            )
            bmpinfo = hbmp.GetInfo()
            bmpstr = hbmp.GetBitmapBits(True)
            img = Image.frombuffer(
                "RGBA",
                (bmpinfo["bmWidth"], bmpinfo["bmHeight"]),
                bmpstr, "raw", "BGRA", 0, 1
            )
            return save_crisp_multi_ico(img, out_ico_path)
        finally:
            hdc_mem.SelectObject(old_bmp)
            win32gui.DeleteObject(hbmp.GetHandle())
            hdc_mem.DeleteDC()
            hdc_screen.DeleteDC()
            win32gui.ReleaseDC(0, screen_dc)
            user32.DestroyIcon(ctypes.c_void_p(hicon))
    except Exception:
        return False


def convert_image_to_ico(src_path: str, out_ico_path: str) -> bool:
    """Converts PNG, JPG, JPEG, JXL, or ICO files into a crisp Windows .ico file."""
    try:
        if src_path.lower().endswith(".ico"):
            shutil.copy2(src_path, out_ico_path)
            return True
        with Image.open(src_path) as img:
            return save_crisp_multi_ico(img.convert("RGBA"), out_ico_path)
    except Exception:
        return False


def _split_command_and_args(raw: str, source_path: str = "") -> tuple[str, str]:
    """Split a command line into (executable_or_script_path, arguments_string).

    When unquoted paths contain spaces (and even folder names ending with .exe),
    evaluates candidate extension boundaries from longest to shortest against the
    filesystem/source_path before falling back to the first extension boundary.
    """
    s = (raw or "").strip()
    if not s:
        return "", ""
    if s.startswith('"'):
        end_q = s.find('"', 1)
        if end_q > 1:
            return s[1:end_q].strip(), s[end_q + 1:].strip()
        return s.strip('"').strip(), ""

    ext_matches = list(re.finditer(r'\.(?:bat|cmd|ps1|exe|msi|reg)(?=\s|$)', s, re.IGNORECASE))
    if ext_matches:
        if len(ext_matches) > 1:
            src_norm = normalize_user_path(source_path) if source_path else ""
            src_dir = (
                src_norm if (src_norm and os.path.isdir(src_norm))
                else (os.path.dirname(src_norm) if src_norm else "")
            )
            for m in reversed(ext_matches):
                cand = s[:m.end()].strip()
                norm_cand = _strip_relative_leading_slashes(cand)
                if os.path.isfile(norm_cand):
                    return cand, s[m.end():].strip()
                if src_dir and not _is_unc_or_drive_abs(cand):
                    if os.path.isfile(os.path.join(src_dir, norm_cand)):
                        return cand, s[m.end():].strip()
        first_m = ext_matches[0]
        return s[:first_m.end()].strip(), s[first_m.end():].strip()

    parts = s.split(None, 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1].strip()


def _resolve_unique_run_file_in_source(source_path: str, raw_run_text: str) -> str:
    """Resolve Run File inside Source Folder unambiguously (including full UNC paths).

    If a bare filename (e.g. 'app.exe') matches multiple files in subdirectories
    (such as 'Client\\app.exe' and 'Server\\app.exe'), return '' so an explicit
    relative path is required.
    """
    src = normalize_user_path(source_path)
    cmd_part, _ = _split_command_and_args(raw_run_text, src)
    if not src or not cmd_part or not os.path.exists(src):
        return ""

    raw_cmd_clean = cmd_part.strip().strip('"')
    is_abs_or_unc = _is_unc_or_drive_abs(raw_cmd_clean)
    candidate = normalize_user_path(raw_cmd_clean) if is_abs_or_unc else _strip_relative_leading_slashes(raw_cmd_clean)
    if not candidate:
        return ""

    if os.path.isfile(src):
        candidate_path = candidate if is_abs_or_unc else os.path.join(os.path.dirname(src), candidate)
        if os.path.isfile(candidate_path) and paths_refer_to_same_location(candidate_path, src):
            return os.path.abspath(src)
        return ""

    if not os.path.isdir(src):
        return ""

    src_real = os.path.normcase(os.path.realpath(os.path.abspath(src)))

    # 1. Explicit absolute or UNC path: verify it is inside src and is an existing file
    if is_abs_or_unc:
        cand_real = os.path.normcase(os.path.realpath(os.path.abspath(candidate)))
        try:
            if os.path.commonpath((src_real, cand_real)) == src_real and os.path.isfile(candidate):
                return os.path.abspath(candidate)
        except ValueError:
            pass
        return ""

    has_explicit_rel_sep = "\\" in raw_cmd_clean.replace("/", "\\").lstrip("\\")
    src_folder_name = os.path.basename(os.path.normpath(src))
    stripped_candidate = candidate
    if src_folder_name and stripped_candidate.lower().startswith(src_folder_name.lower() + "\\"):
        stripped_candidate = stripped_candidate[len(src_folder_name) + 1:].lstrip("\\")

    # 2. Explicit relative path with directory separator (e.g. 'Client\app.exe' or '.\app.exe')
    if has_explicit_rel_sep or "\\" in stripped_candidate:
        for rel_try in (candidate, stripped_candidate):
            if not rel_try:
                continue
            cand_path = os.path.join(src, rel_try)
            cand_real = os.path.normcase(os.path.realpath(os.path.abspath(cand_path)))
            try:
                if os.path.commonpath((src_real, cand_real)) == src_real and os.path.isfile(cand_path):
                    return os.path.abspath(cand_path)
            except ValueError:
                pass
        return ""

    # 3. Bare filename without directory separator (e.g. 'app.exe'): must be unique across the source tree
    target_cf = stripped_candidate.casefold()
    matches: list[str] = []
    for folder, _, files in os.walk(src):
        for fname in files:
            if (fname.startswith(".bw_staging_") and fname.endswith(".tmp")) or fname.endswith(".bw_res"):
                continue
            if fname.casefold() == target_cf:
                matches.append(os.path.abspath(os.path.join(folder, fname)))
                if len(matches) > 1:
                    return ""

    if len(matches) == 1:
        return matches[0]
    return ""


# ==========================================
# SMART CLICKABLE & DRAG-DROP LINE EDIT
# ==========================================
class SmartLineEdit(QLineEdit):
    """
    Supports direct typing, drag-and-drop, and pops up an English selection menu
    when right-clicked (or when left-clicked while empty).
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
        if event.button() == Qt.MouseButton.LeftButton and not self.text().strip():
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

    def _format_run_file_selection(self, file_path: str) -> str:
        """Convert selected/dropped run file path to an unambiguous relative path inside Source."""
        norm_file = normalize_user_path(file_path)
        start_dir = ""
        if self.parent_win:
            src = normalize_user_path(self.parent_win.inp_source.text())
            if os.path.isdir(src):
                start_dir = src
            elif os.path.isfile(src):
                start_dir = os.path.dirname(src)

        if start_dir:
            try:
                norm_file_real = os.path.normcase(os.path.realpath(os.path.abspath(norm_file)))
                start_real = os.path.normcase(os.path.realpath(os.path.abspath(start_dir)))
                if os.path.commonpath((start_real, norm_file_real)) == start_real:
                    rel_path = os.path.relpath(
                        os.path.realpath(os.path.abspath(norm_file)),
                        os.path.realpath(os.path.abspath(start_dir)),
                    )
                    if "\\" not in rel_path and "/" not in rel_path and os.path.isdir(start_dir):
                        if not _resolve_unique_run_file_in_source(start_dir, rel_path):
                            return f".\\{rel_path}"
                    return rel_path
            except ValueError:
                pass
        return norm_file

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
                    self.setText(normalize_user_path(folder))
            elif action == act_file:
                file_path, _ = QFileDialog.getOpenFileName(self, "Select Source File")
                if file_path:
                    self.setText(normalize_user_path(file_path))
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
                    self.setText(normalize_user_path(folder))
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
                    self.setText(normalize_user_path(folder))
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
                    src = normalize_user_path(self.parent_win.inp_source.text())
                    if os.path.isdir(src):
                        start_dir = src
                    elif os.path.isfile(src):
                        start_dir = os.path.dirname(src)

                file_path, _ = QFileDialog.getOpenFileName(
                    self, "Select File to Run After Extraction", start_dir
                )
                if file_path:
                    self.setText(self._format_run_file_selection(file_path))
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
                    dropped_path = normalize_user_path(local_path)
                    if (self.parent_win is not None
                            and os.path.isfile(dropped_path)
                            and dropped_path.lower().endswith(".json")):
                        self.parent_win.import_config_from_path(dropped_path)
                        event.acceptProposedAction()
                        return
                    if self.mode == "source" and self.parent_win is not None:
                        self.parent_win.on_source_dropped(dropped_path)
                    elif self.mode == "run_file":
                        self.setText(self._format_run_file_selection(dropped_path))
                    else:
                        self.setText(dropped_path)
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
                return normalize_user_path(path)
        return ''

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setToolTip('Click to inspect an EXE/SFX or drop it here to open its config in your default editor.')

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


def _looks_like_self_elevating_script(path: str) -> bool:
    """Recognize common script self-elevation patterns without executing the script."""
    try:
        if not path or not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext not in (".bat", ".cmd", ".ps1"):
            return False
        with open(path, "rb") as f:
            content = f.read(512 * 1024).decode("utf-8-sig", errors="replace")
        lines = [line for line in content.splitlines()
                 if not re.match(r"^\s*(?:rem\s|::|#)", line, re.IGNORECASE)]
        active = "\n".join(lines)
        if ext == ".ps1":
            return bool(re.search(r"(?i)\bstart-process\b[^\r\n]*\s-verb\s+['\"]?runas\b", active))
        if re.search(r"(?im)^.*\b(?:fltmc|net\s+session)\b[^\r\n]*\|\|[^\r\n]*\bstart\b", active):
            return True
        return bool(re.search(r"(?i)\bstart-process\b[^\r\n]*-verb\s+['\"]?runas\b", active))
    except (OSError, UnicodeError):
        return False


def _remove_build_directory_safely(path: str) -> bool:
    """Retry transient Windows sharing violations without atexit cleanup errors."""
    for attempt in range(9):
        try:
            shutil.rmtree(path)
            return True
        except FileNotFoundError:
            return True
        except OSError as exc:
            if attempt == 8 or (getattr(exc, "winerror", None) not in (5, 32)
                                and not isinstance(exc, PermissionError)):
                return False
            time.sleep(0.25 + attempt * 0.15)
    return False


# ==========================================
# BACKGROUND SFX BUILDER THREAD
# ==========================================
class SFXBuilderWorker(QThread):
    progress = pyqtSignal(int)
    build_finished = pyqtSignal(bool, str)

    SEVENZIP_TIMEOUT_SEC = 1800  # 30 minutes max for compression
    CSC_TIMEOUT_SEC = 120        # 2 minutes max for C# stub compilation
    MAX_LOG_CHARS = 8192         # Bounded buffer size for 7-Zip output
    DICT_SCAN_CAP_BYTES = 65 * 1024 * 1024  # >64 MB always selects -md=128m
    _KNOWN_BUILT_OUTPUTS: set[str] = set()
    _OUTPUT_LOCK = threading.Lock()

    def __init__(self, config: dict):
        super().__init__()
        self.cfg = config
        self._cancelled = False
        self._proc_lock = threading.Lock()
        self._active_proc: subprocess.Popen | None = None
        self._reserved_target_path: str = ""
        self._reserved_lock_file: str = ""
        self.output_exe_path: str = ""

    @staticmethod
    def _terminate_process_tree(proc: subprocess.Popen | None):
        """Terminate a child process and all of its descendants, then wait for exit."""
        if proc is None:
            return
        try:
            if proc.poll() is None:
                pid = proc.pid
                if os.name == "nt" and pid:
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(pid)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=5,
                        )
                    except Exception:
                        pass
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        except Exception:
            pass

    def _release_reservation_lock(self):
        """Remove the companion .bw_res lock file for this worker."""
        lock_file = self._reserved_lock_file
        self._reserved_lock_file = ""
        self._reserved_target_path = ""
        if lock_file and os.path.isfile(lock_file):
            try:
                os.unlink(lock_file)
            except OSError:
                pass

    def cancel(self):
        """Request cancellation and terminate any active external process tree without blocking the GUI."""
        self._cancelled = True
        with self._proc_lock:
            proc = self._active_proc
        if proc is not None:
            threading.Thread(
                target=self._terminate_process_tree,
                args=(proc,),
                daemon=True,
            ).start()

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

    def _get_source_total_size(self, source_path: str) -> int:
        """Scan source size with cancellation checks and early stop once >64 MB."""
        if self._cancelled:
            raise RuntimeError("Canceled by user.")
        if os.path.isfile(source_path):
            try:
                return os.path.getsize(source_path)
            except OSError:
                return 0
        total = 0
        for root, _, files in os.walk(source_path):
            if self._cancelled:
                raise RuntimeError("Canceled by user.")
            for name in files:
                if self._cancelled:
                    raise RuntimeError("Canceled by user.")
                if (name.startswith(".bw_staging_") and name.endswith(".tmp")) or name.endswith(".bw_res"):
                    continue
                try:
                    total += os.path.getsize(os.path.join(root, name))
                    if total >= self.DICT_SCAN_CAP_BYTES:
                        return total
                except OSError:
                    pass
        return total

    @staticmethod
    def _select_7z_dict_flag(total_bytes: int) -> str:
        """Choose an LZMA2 dictionary size proportional to the input size to save RAM."""
        mb = total_bytes / (1024 * 1024)
        if mb <= 8:
            return "-md=8m"
        if mb <= 16:
            return "-md=16m"
        if mb <= 32:
            return "-md=32m"
        if mb <= 64:
            return "-md=64m"
        return "-md=128m"

    @staticmethod
    def sanitize_package_base_name(raw_name: str) -> str:
        name = (raw_name or "").strip() or "Package"
        if name.lower().endswith(".exe"):
            name = name[:-4]
        name = re.sub(r'[<>:"/\\|?*]', '_', name).strip().rstrip(". ") or "Package"
        if is_windows_reserved_name(name):
            name = f"_{name}"
        return name

    @classmethod
    def _try_acquire_reservation_lock(cls, target_candidate: str) -> str:
        """Atomically acquire a companion '<target_candidate>.bw_res' lock file if target does not exist.

        Using a '.bw_res' companion file instead of a 0-byte '.exe' ensures that:
        1. Two concurrent workers/processes never pick the same target_exe name.
        2. No 0-byte '.exe' file ever exists in the source directory to be archived by 7-Zip.
        """
        if os.path.exists(target_candidate):
            return ""

        lock_path = f"{target_candidate}.bw_res"
        for _ in range(2):
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
                try:
                    os.write(fd, f"{os.getpid()}\n".encode("ascii"))
                finally:
                    os.close(fd)
                # Verify target_candidate was not created right before lock acquisition
                if os.path.exists(target_candidate):
                    try:
                        os.unlink(lock_path)
                    except OSError:
                        pass
                    return ""
                return lock_path
            except OSError as exc:
                if exc.errno != errno.EEXIST and not os.path.exists(lock_path):
                    raise
                # Check if the existing .bw_res lock belongs to a dead process
                try:
                    age = time.time() - os.path.getmtime(lock_path)
                    if age > 30:
                        with open(lock_path, "r", encoding="ascii", errors="ignore") as f:
                            pid_str = f.read().strip()
                        owner_pid = int(pid_str) if pid_str.isdigit() else 0
                        if owner_pid > 0 and owner_pid != os.getpid() and not _is_pid_running(owner_pid):
                            os.unlink(lock_path)
                            continue
                except OSError:
                    pass
                return ""
        return ""

    @staticmethod
    def _try_move_no_overwrite(src_path: str, dst_path: str) -> bool:
        """Atomically move src_path to dst_path while strictly refusing to overwrite an existing file."""
        if os.name == "nt" and _win32_k32 is not None:
            ctypes.set_last_error(0)
            # dwFlags = 0 -> Do NOT set MOVEFILE_REPLACE_EXISTING
            if _win32_k32.MoveFileExW(src_path, dst_path, 0):
                return True
            return False
        try:
            os.link(src_path, dst_path)
            os.unlink(src_path)
            return True
        except OSError:
            return False

    def _iter_dont_replace_candidates(self, out_dir: str, name: str):
        """Yield candidate output paths in deterministic order for Don't Replace."""
        yield os.path.join(out_dir, f"{name}.exe")
        fs_stamp = datetime.now().strftime("%d.%m.%Y %H.%M.%S")
        yield os.path.join(out_dir, f"{name}_{fs_stamp}.exe")
        counter = 2
        while True:
            yield os.path.join(out_dir, f"{name}_{fs_stamp} ({counter}).exe")
            counter += 1

    def resolve_output_exe_path(self) -> str:
        """Resolve (and atomically reserve via .bw_res when Don't Replace is enabled) the output EXE path."""
        out_dir = normalize_user_path(self.cfg["output"])
        os.makedirs(out_dir, exist_ok=True)
        name = self.sanitize_package_base_name(self.cfg["name"])

        if not self.cfg["dont_replace"]:
            return os.path.join(out_dir, f"{name}.exe")

        if (self._reserved_target_path
                and self._reserved_lock_file
                and os.path.isfile(self._reserved_lock_file)
                and not os.path.exists(self._reserved_target_path)):
            return self._reserved_target_path

        with self._OUTPUT_LOCK:
            for candidate in self._iter_dont_replace_candidates(out_dir, name):
                lock_file = self._try_acquire_reservation_lock(candidate)
                if lock_file:
                    self._reserved_target_path = candidate
                    self._reserved_lock_file = lock_file
                    return candidate

    def _commit_staging_exe(self, staging_exe: str, target_exe: str) -> str:
        """Move staging_exe to its final destination, guaranteeing no overwrite if Don't Replace is enabled."""
        out_dir = os.path.dirname(target_exe)
        name = self.sanitize_package_base_name(self.cfg["name"])

        if not self.cfg["dont_replace"]:
            os.replace(staging_exe, target_exe)
            with self._OUTPUT_LOCK:
                self._KNOWN_BUILT_OUTPUTS.add(os.path.normcase(os.path.realpath(os.path.abspath(target_exe))))
            return target_exe

        with self._OUTPUT_LOCK:
            try:
                if not os.path.exists(target_exe) and self._try_move_no_overwrite(staging_exe, target_exe):
                    self._KNOWN_BUILT_OUTPUTS.add(
                        os.path.normcase(os.path.realpath(os.path.abspath(target_exe)))
                    )
                    return target_exe

                for candidate in self._iter_dont_replace_candidates(out_dir, name):
                    if os.path.exists(candidate):
                        continue
                    # Respect active .bw_res locks held by other concurrent workers
                    other_lock = f"{candidate}.bw_res"
                    if os.path.exists(other_lock) and other_lock != self._reserved_lock_file:
                        continue
                    if self._try_move_no_overwrite(staging_exe, candidate):
                        self._KNOWN_BUILT_OUTPUTS.add(
                            os.path.normcase(os.path.realpath(os.path.abspath(candidate)))
                        )
                        return candidate
            finally:
                self._release_reservation_lock()

    def get_internal_7z_password(self) -> str:
        if self.cfg["use_password"] and self.cfg["password"]:
            return self.cfg["password"]
        if self.cfg["crypto"]:
            return "byte"
        return ""

    def _compute_7z_exclusions(self, source_path: str, target_exe: str, run_script_path: str = "") -> list[str]:
        """Exclude staging files, .bw_res locks, target_exe, and verified Byte Wrapper SFX outputs."""
        exclusions = [
            "-x!*.bw_staging_*.tmp",
            "-x!.bw_staging_*.tmp",
            "-x!*.bw_res",
            "-x!.bw_res*",
        ]
        if not os.path.isdir(source_path):
            return exclusions

        src_real = os.path.realpath(os.path.abspath(source_path))
        src_real_nc = os.path.normcase(src_real)
        out_dir_real = os.path.realpath(os.path.abspath(os.path.dirname(target_exe)))
        out_dir_real_nc = os.path.normcase(out_dir_real)
        try:
            common = os.path.commonpath((src_real_nc, out_dir_real_nc))
        except ValueError:
            return exclusions

        if common != src_real_nc:
            return exclusions

        run_real_nc = (
            os.path.normcase(os.path.realpath(os.path.abspath(run_script_path)))
            if run_script_path and os.path.exists(run_script_path)
            else ""
        )

        files_to_exclude: set[str] = set()
        target_real = os.path.realpath(os.path.abspath(target_exe))
        if os.path.normcase(target_real) != run_real_nc:
            files_to_exclude.add(target_real)

        # Scan existing .exe files in out_dir and exclude verified Byte Wrapper SFX packages
        # or files that currently have an active .bw_res companion reservation lock.
        if os.path.isdir(out_dir_real):
            try:
                for entry in os.scandir(out_dir_real):
                    if not entry.is_file() or not entry.name.lower().endswith(".exe"):
                        continue
                    cand_real = os.path.realpath(entry.path)
                    cand_real_nc = os.path.normcase(cand_real)
                    if cand_real_nc == run_real_nc:
                        continue
                    with self._OUTPUT_LOCK:
                        is_known = cand_real_nc in self._KNOWN_BUILT_OUTPUTS
                    has_res_lock = os.path.exists(f"{entry.path}.bw_res")
                    if is_known or has_res_lock or _is_byte_wrapper_sfx_file(cand_real):
                        files_to_exclude.add(cand_real)
            except OSError:
                pass

        for exc_abs in sorted(files_to_exclude):
            try:
                rel_exc = os.path.relpath(exc_abs, src_real).replace("/", "\\")
                if rel_exc and not rel_exc.startswith(".."):
                    exclusions.append(f"-x!{rel_exc}")
            except ValueError:
                pass

        return exclusions

    @staticmethod
    def _normalize_run_command_for_stub(source_path: str, raw_run_cmd: str) -> str:
        """Convert run file paths inside Source into portable relative paths for the C# stub."""
        cmd_part, args_part = _split_command_and_args(raw_run_cmd, source_path)
        if not cmd_part:
            return ""
        rel_cmd = _strip_relative_leading_slashes(cmd_part)

        if os.path.isfile(source_path):
            rel_cmd = os.path.basename(source_path)
        elif os.path.isdir(source_path):
            resolved = _resolve_unique_run_file_in_source(source_path, raw_run_cmd)
            if resolved:
                try:
                    rel_cmd = os.path.relpath(
                        os.path.realpath(os.path.abspath(resolved)),
                        os.path.realpath(os.path.abspath(source_path)),
                    )
                except ValueError:
                    pass

        if " " in rel_cmd and not rel_cmd.startswith('"'):
            rel_cmd = f'"{rel_cmd}"'
        return f"{rel_cmd} {args_part}".strip() if args_part else rel_cmd

    def build_7z_archive(self, seven_zip: str, source_path: str, archive_path: str, target_exe: str, run_script_path: str = "") -> subprocess.CompletedProcess:
        cmd = [seven_zip, "a", "-bsp1"]

        if self.cfg["compress"]:
            dict_flag = self._select_7z_dict_flag(self._get_source_total_size(source_path))
            cmd.extend([
                "-t7z",
                "-mx=9",
                "-m0=lzma2",
                dict_flag,
                "-mfb=64",
                "-ms=16g",
                "-mmt=on"
            ])
        else:
            cmd.extend(["-t7z", "-mx=0", "-mmt=on"])

        internal_pw = self.get_internal_7z_password()
        if internal_pw:
            cmd.extend([f"-p{internal_pw}", "-mhe=on"])

        cmd.extend(self._compute_7z_exclusions(source_path, target_exe, run_script_path))
        cmd.extend(["-y", archive_path])

        if os.path.isdir(source_path):
            cmd.append(os.path.join(source_path, "*"))
        else:
            cmd.append(source_path)

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creation_flags
        )
        with self._proc_lock:
            self._active_proc = proc

        if self._cancelled:
            self._terminate_process_tree(proc)
            with self._proc_lock:
                self._active_proc = None
            raise RuntimeError("Canceled by user.")

        timed_out = False

        def _on_timeout():
            nonlocal timed_out
            timed_out = True
            self._terminate_process_tree(proc)

        timer = threading.Timer(self.SEVENZIP_TIMEOUT_SEC, _on_timeout)
        timer.daemon = True
        timer.start()

        tail_chars: deque[str] = deque(maxlen=self.MAX_LOG_CHARS)
        pct_pattern = re.compile(r"(\d{1,3})%")
        try:
            if proc.stdout is not None:
                buf = ""
                while True:
                    if self._cancelled:
                        self._terminate_process_tree(proc)
                        raise RuntimeError("Canceled by user.")
                    ch = proc.stdout.read(1)
                    if not ch:
                        break
                    tail_chars.append(ch)
                    if ch in ("\r", "\n", "\b"):
                        m = pct_pattern.search(buf)
                        if m:
                            pct = min(100, max(0, int(m.group(1))))
                            mapped = 20 + int((pct / 100.0) * 40)
                            self.progress.emit(mapped)
                        buf = ""
                    else:
                        buf += ch
                        if len(buf) > 128:
                            buf = buf[-64:]

            ret = proc.wait()
            if self._cancelled:
                self._terminate_process_tree(proc)
                raise RuntimeError("Canceled by user.")
            if timed_out:
                self._terminate_process_tree(proc)
                raise TimeoutError("7-Zip compression timed out.")
            combined_output = "".join(tail_chars)
            return subprocess.CompletedProcess(cmd, ret, combined_output, "")
        finally:
            timer.cancel()
            with self._proc_lock:
                self._active_proc = None

    def prepare_payload(self, raw_7z_path: str, out_dat_path: str) -> tuple[str, bool]:
        if not self.cfg["crypto"]:
            return raw_7z_path, False

        key_bytes = b"byte_wrapper_secret_key"
        key_len = len(key_bytes)
        period = key_len * 256
        base_mask = bytes(
            key_bytes[i % key_len] ^ ((i & 0xFF) ^ 0xA5)
            for i in range(period)
        )

        chunk_size = period * 178  # 1,048,064 bytes (~1 MB)
        full_mask = base_mask * 178
        full_mask_int = int.from_bytes(full_mask, "little")

        total_size = max(1, os.path.getsize(raw_7z_path))
        processed = 0
        last_emitted = 60

        with open(raw_7z_path, "rb") as fin, open(out_dat_path, "wb") as fout:
            while True:
                if self._cancelled:
                    raise RuntimeError("Canceled by user.")
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                n = len(chunk)
                if n == chunk_size:
                    xored = int.from_bytes(chunk, "little") ^ full_mask_int
                else:
                    sub_mask_int = int.from_bytes(full_mask[:n], "little")
                    xored = int.from_bytes(chunk, "little") ^ sub_mask_int
                fout.write(xored.to_bytes(n, "little"))
                processed += n
                mapped = 60 + int((processed / total_size) * 15)
                if mapped != last_emitted:
                    last_emitted = mapped
                    self.progress.emit(mapped)

        if self._cancelled:
            raise RuntimeError("Canceled by user.")

        return out_dat_path, True

    def compile_csharp_sfx(self, csc_path: str, work_dir: str, payload_dat: str, scrambled: bool, seven_zip: str, staging_exe: str) -> tuple[bool, str]:
        """Compile the C# stub and append the payload into staging_exe (never touching an existing target_exe)."""
        if self._cancelled:
            return False, "Canceled by user."

        shutil.copy2(seven_zip, os.path.join(work_dir, "7z.exe"))
        seven_zip_dll = os.path.join(os.path.dirname(seven_zip), "7z.dll")
        has_dll = os.path.isfile(seven_zip_dll)
        if has_dll:
            shutil.copy2(seven_zip_dll, os.path.join(work_dir, "7z.dll"))

        src_norm = normalize_user_path(self.cfg["source"])
        source_folder_name = os.path.basename(src_norm) if os.path.isdir(src_norm) else ""
        portable_run_cmd = self._normalize_run_command_for_stub(src_norm, self.cfg["run_file"])

        def cs_escape(s: str) -> str:
            return (
                s.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
            )

        prod_name_str = cs_escape(self.cfg["name"].strip() or "Byte Wrapper Package")
        raw_desc = self.cfg["description"].strip()
        file_desc_str = cs_escape(raw_desc if raw_desc else (self.cfg["name"].strip() or "Byte Wrapper Package"))

        pe_ver_num, pe_ver_info = _normalize_pe_version(self.cfg.get("version", ""))
        pe_ver_num_str = cs_escape(pe_ver_num)
        pe_ver_info_str = cs_escape(pe_ver_info)

        extract_to_str = cs_escape(self.cfg["extract_to"].strip())
        run_file_str = cs_escape(portable_run_cmd)
        source_folder_name_str = cs_escape(source_folder_name)

        has_user_pw = bool(self.cfg["use_password"] and self.cfg["password"])
        ask_user_pw = "true" if has_user_pw else "false"
        if has_user_pw:
            expected_user_pw_hash = hashlib.sha256(self.cfg["password"].encode("utf-8")).hexdigest().lower()
            internal_7z_pw = ""
        else:
            expected_user_pw_hash = ""
            internal_7z_pw = cs_escape(self.get_internal_7z_password())

        is_scrambled = "true" if scrambled else "false"
        overlay_archive_size = os.path.getsize(payload_dat)
        hidden_run = "true" if self.cfg["hidden_run"] else "false"
        hidden_script_needs_admin = "true" if (
            self.cfg["hidden_run"]
            and not self.cfg["run_as_admin"]
            and self.cfg.get("self_elevating_run_file", False)
        ) else "false"
        extract_only = "true" if self.cfg["extract_only"] else "false"
        instances = "true" if self.cfg["instances"] else "false"
        self_remove = "true" if self.cfg["self_remove"] else "false"
        show_progress = "true" if self.cfg["progress_bar"] else "false"

        exec_level = "requireAdministrator" if self.cfg["run_as_admin"] else "asInvoker"
        safe_xml_ver = xml_escape(pe_ver_num, {'"': '&quot;', "'": '&apos;'})
        safe_xml_level = xml_escape(exec_level, {'"': '&quot;', "'": '&apos;'})
        manifest_path = os.path.join(work_dir, "app.manifest")
        manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="{safe_xml_ver}" name="ByteWrapper.Package"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="{safe_xml_level}" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"""
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(manifest_xml)

        def build_cs_source(pw_literal: str, hash_literal: str) -> str:
            return rf"""
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Drawing;
using System.Reflection;
using System.Diagnostics;
using System.ComponentModel;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Windows.Forms;

[assembly: AssemblyTitle("{file_desc_str}")]
[assembly: AssemblyDescription("{file_desc_str}")]
[assembly: AssemblyProduct("{prod_name_str}")]
[assembly: AssemblyCompany("Byte Wrapper")]
[assembly: AssemblyVersion("{pe_ver_num_str}")]
[assembly: AssemblyFileVersion("{pe_ver_num_str}")]
[assembly: AssemblyInformationalVersion("{pe_ver_info_str}")]

namespace ByteWrapperStub
{{
    static class Program
    {{
        private static readonly string EXTRACT_TO = "{extract_to_str}";
        private static readonly string RUN_FILE = "{run_file_str}";
        private static readonly string SOURCE_FOLDER_NAME = "{source_folder_name_str}";
        private static readonly string INTERNAL_7Z_PW = "{pw_literal}";
        private static readonly bool ASK_USER_PW = {ask_user_pw};
        private static readonly string EXPECTED_USER_PW_HASH = "{hash_literal}";
        private static readonly bool IS_SCRAMBLED = {is_scrambled};
        private static readonly long OVERLAY_ARCHIVE_SIZE = {overlay_archive_size}L;
        private static readonly bool HIDDEN_RUN = {hidden_run};
        private static readonly bool HIDDEN_SCRIPT_NEEDS_ADMIN = {hidden_script_needs_admin};
        private static readonly bool EXTRACT_ONLY = {extract_only};
        private static readonly bool INSTANCES = {instances};
        private static readonly bool SELF_REMOVE = {self_remove};
        private static readonly bool SHOW_PROGRESS = {show_progress};
        private const string TEMP_MARKER_FILE = ".bw_temp_marker";

        private const int STARTF_USESHOWWINDOW = 0x00000001;
        private const short SW_HIDE = 0;
        private const uint CREATE_NO_WINDOW = 0x08000000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {{
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }}

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {{
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }}

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(
            string lpApplicationName,
            StringBuilder lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static string ComputeSha256Hex(string text)
        {{
            using (SHA256 sha = SHA256.Create())
            {{
                byte[] bytes = Encoding.UTF8.GetBytes(text ?? "");
                byte[] hash = sha.ComputeHash(bytes);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++)
                    sb.Append(hash[i].ToString("x2"));
                return sb.ToString();
            }}
        }}

        private static string StripLeadingRelativeSlashes(string path)
        {{
            if (string.IsNullOrEmpty(path))
                return "";
            if (path.StartsWith(@"\\"))
                return path;
            return path.TrimStart('\\', '/');
        }}

        private static string Format7zPasswordSwitch(string pw)
        {{
            if (string.IsNullOrEmpty(pw))
                return "";
            StringBuilder sb = new StringBuilder();
            int backslashes = 0;
            foreach (char c in pw)
            {{
                if (c == '\\')
                {{
                    backslashes++;
                }}
                else if (c == '"')
                {{
                    sb.Append('\\', backslashes * 2 + 1);
                    sb.Append('"');
                    backslashes = 0;
                }}
                else
                {{
                    if (backslashes > 0)
                    {{
                        sb.Append('\\', backslashes);
                        backslashes = 0;
                    }}
                    sb.Append(c);
                }}
            }}
            if (backslashes > 0)
                sb.Append('\\', backslashes * 2);
            return "-p\"" + sb.ToString() + "\" ";
        }}

        private static void WriteTempMarker(string dirPath)
        {{
            try
            {{
                string markerPath = Path.Combine(dirPath, TEMP_MARKER_FILE);
                File.WriteAllText(markerPath, "ByteWrapperTemp");
                File.SetAttributes(markerPath, FileAttributes.Hidden);
            }}
            catch {{ }}
        }}

        private static bool HasTempMarker(string dirPath)
        {{
            try
            {{
                return File.Exists(Path.Combine(dirPath, TEMP_MARKER_FILE));
            }}
            catch
            {{
                return false;
            }}
        }}

        private static bool TryDeleteDirectoryIfUnused(string dirPath, bool requireMarker)
        {{
            if (string.IsNullOrEmpty(dirPath) || !Directory.Exists(dirPath))
                return true;

            if (requireMarker && !HasTempMarker(dirPath))
                return false;

            string trimmed = dirPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string parentDir = Path.GetDirectoryName(trimmed);
            if (string.IsNullOrEmpty(parentDir))
                return false;

            string probePath = Path.Combine(parentDir, ".bw_del_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            try
            {{
                // Atomic rename on the same NTFS volume fails without deleting or locking any file
                // if any file/handle or working directory inside trimmed is open.
                Directory.Move(trimmed, probePath);
            }}
            catch
            {{
                return false;
            }}

            try
            {{
                Directory.Delete(probePath, true);
                return true;
            }}
            catch
            {{
                try
                {{
                    if (Directory.Exists(probePath) && !Directory.Exists(trimmed))
                        Directory.Move(probePath, trimmed);
                }}
                catch {{ }}
                return false;
            }}
        }}

        private static void StartBackgroundStaleCleanup()
        {{
            ThreadPool.QueueUserWorkItem(delegate
            {{
                try
                {{
                    string tempRoot = Path.GetTempPath();
                    DateTime threshold = DateTime.UtcNow.AddHours(-6);
                    foreach (string pattern in new string[] {{ "BytePkg_*", "bw_rt_*" }})
                    {{
                        string[] dirs;
                        try {{ dirs = Directory.GetDirectories(tempRoot, pattern); }}
                        catch {{ continue; }}
                        foreach (string dir in dirs)
                        {{
                            try
                            {{
                                if (Directory.GetLastWriteTimeUtc(dir) < threshold)
                                    TryDeleteDirectoryIfUnused(dir, true);
                            }}
                            catch {{ }}
                        }}
                    }}
                }}
                catch {{ }}
            }});
        }}

        private static bool IsTempRootPath(string rawExtractTo)
        {{
            if (string.IsNullOrWhiteSpace(rawExtractTo))
                return true;
            string trimmed = rawExtractTo.Trim().Trim('"');
            if (string.Equals(trimmed, "%Temp%", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(trimmed, "%TMP%", StringComparison.OrdinalIgnoreCase))
                return true;
            try
            {{
                string expanded = Path.GetFullPath(Environment.ExpandEnvironmentVariables(trimmed.Replace("/", "\\")))
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string sysTemp = Path.GetFullPath(Path.GetTempPath())
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                return string.Equals(expanded, sysTemp, StringComparison.OrdinalIgnoreCase);
            }}
            catch
            {{
                return false;
            }}
        }}

        [STAThread]
        static void Main()
        {{
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            StartBackgroundStaleCleanup();

            if (HIDDEN_RUN && HIDDEN_SCRIPT_NEEDS_ADMIN && !IsRunningAsAdministrator())
            {{
                RelaunchPackageElevatedHidden();
                return;
            }}

            string runtime7zPw = INTERNAL_7Z_PW;
            if (ASK_USER_PW)
            {{
                string inputPw = PromptPassword();
                if (inputPw == null)
                    return;
                if (!string.Equals(ComputeSha256Hex(inputPw), EXPECTED_USER_PW_HASH, StringComparison.OrdinalIgnoreCase))
                {{
                    MessageBox.Show("Invalid password!", "{prod_name_str}", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }}
                runtime7zPw = inputPw;
            }}

            bool extractToIsTempRoot = IsTempRootPath(EXTRACT_TO);
            bool isTempExtraction = !EXTRACT_ONLY && extractToIsTempRoot;
            string targetDir;
            if (isTempExtraction)
            {{
                targetDir = Path.Combine(Path.GetTempPath(), "BytePkg_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            }}
            else if (EXTRACT_ONLY && extractToIsTempRoot)
            {{
                // Persistent isolated folder for Extract Only when Extract To was left empty or set to %Temp%
                string uniqueSuffix = Guid.NewGuid().ToString("N").Substring(0, 8);
                string subFolder = !string.IsNullOrEmpty(SOURCE_FOLDER_NAME)
                    ? (SOURCE_FOLDER_NAME + "_" + uniqueSuffix)
                    : ("ByteExtract_" + uniqueSuffix);
                targetDir = Path.Combine(Path.GetTempPath(), subFolder);
            }}
            else
            {{
                targetDir = Environment.ExpandEnvironmentVariables(EXTRACT_TO.Replace("/", "\\").Trim().Trim('"'));
            }}

            if (!isTempExtraction && !string.IsNullOrEmpty(SOURCE_FOLDER_NAME) && !string.IsNullOrEmpty(RUN_FILE))
            {{
                string expandedRun = Environment.ExpandEnvironmentVariables(RUN_FILE.Replace("/", "\\")).Trim().Trim('"');
                string expectedSub = Path.Combine(targetDir, SOURCE_FOLDER_NAME);
                if ((expandedRun.StartsWith(expectedSub + "\\", StringComparison.OrdinalIgnoreCase) ||
                     expandedRun.StartsWith(SOURCE_FOLDER_NAME + "\\", StringComparison.OrdinalIgnoreCase)) &&
                    !targetDir.EndsWith(SOURCE_FOLDER_NAME, StringComparison.OrdinalIgnoreCase))
                {{
                    targetDir = expectedSub;
                }}
            }}

            try
            {{
                Directory.CreateDirectory(targetDir);
                if (isTempExtraction)
                    WriteTempMarker(targetDir);
            }}
            catch (Exception ex)
            {{
                if (!HIDDEN_RUN)
                    MessageBox.Show("Failed to create target directory: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }}

            string workTemp = Path.Combine(Path.GetTempPath(), "bw_rt_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(workTemp);
            WriteTempMarker(workTemp);

            Exception extractError = null;
            int launchedPid = 0;

            try
            {{
                Action<Action<int>> extractAction = delegate(Action<int> reportProgress)
                {{
                    try
                    {{
                        string sevenZExe = Path.Combine(workTemp, "7z.exe");
                        string sevenZDll = Path.Combine(workTemp, "7z.dll");
                        string archive7z = Path.Combine(workTemp, "pkg.7z");

                        ExtractResource("7z.exe", sevenZExe);
                        ExtractResourceIfExists("7z.dll", sevenZDll);
                        ExtractOverlayArchive(archive7z, IS_SCRAMBLED, reportProgress);

                        StringBuilder args = new StringBuilder();
                        args.Append("x -bsp1 \"" + archive7z + "\" ");
                        args.Append("-o\"" + targetDir + "\" ");
                        if (!string.IsNullOrEmpty(runtime7zPw))
                        {{
                            args.Append(Format7zPasswordSwitch(runtime7zPw));
                        }}
                        args.Append(INSTANCES ? "-aos -y" : "-aoa -y");

                        ProcessStartInfo psi7z = new ProcessStartInfo();
                        psi7z.FileName = sevenZExe;
                        psi7z.Arguments = args.ToString();
                        psi7z.UseShellExecute = false;
                        psi7z.CreateNoWindow = true;
                        psi7z.WindowStyle = ProcessWindowStyle.Hidden;
                        psi7z.RedirectStandardOutput = true;
                        psi7z.RedirectStandardError = true;

                        using (Process p = new Process())
                        {{
                            p.StartInfo = psi7z;
                            p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e) {{ }};
                            if (!p.Start())
                                throw new InvalidOperationException("7-Zip extractor could not start.");
                            p.BeginErrorReadLine();

                            Regex pctRegex = new Regex(@"(\d{{1,3}})%");
                            StringBuilder lineBuf = new StringBuilder();
                            int ch;
                            while ((ch = p.StandardOutput.Read()) != -1)
                            {{
                                char c = (char)ch;
                                if (c == '\r' || c == '\n' || c == '\b')
                                {{
                                    if (lineBuf.Length > 0)
                                    {{
                                        Match m = pctRegex.Match(lineBuf.ToString());
                                        if (m.Success)
                                        {{
                                            int pct;
                                            if (int.TryParse(m.Groups[1].Value, out pct))
                                            {{
                                                if (pct < 0) pct = 0;
                                                if (pct > 100) pct = 100;
                                                if (reportProgress != null)
                                                    reportProgress(50 + (pct / 2));
                                            }}
                                        }}
                                        lineBuf.Length = 0;
                                    }}
                                }}
                                else
                                {{
                                    lineBuf.Append(c);
                                    if (lineBuf.Length > 128)
                                        lineBuf.Remove(0, 64);
                                }}
                            }}

                            p.WaitForExit();
                            if (p.ExitCode != 0)
                                throw new InvalidDataException("7-Zip extraction failed with exit code " + p.ExitCode);
                            if (reportProgress != null)
                                reportProgress(100);
                        }}

                        try {{ File.Delete(archive7z); }} catch {{ }}
                    }}
                    catch (Exception ex)
                    {{
                        extractError = ex;
                    }}
                }};

                if (SHOW_PROGRESS && !HIDDEN_RUN)
                {{
                    ProgressBar pbControl;
                    Label lblControl;
                    using (Form progressForm = CreateProgressForm(out pbControl, out lblControl))
                    {{
                        Action<int> uiReporter = delegate(int val)
                        {{
                            try
                            {{
                                if (progressForm.IsHandleCreated && !progressForm.IsDisposed)
                                {{
                                    progressForm.BeginInvoke((MethodInvoker)delegate
                                    {{
                                        if (!pbControl.IsDisposed)
                                        {{
                                            int clamped = Math.Max(0, Math.Min(100, val));
                                            pbControl.Value = clamped;
                                            lblControl.Text = "Extracting package... " + clamped + "%";
                                        }}
                                    }});
                                }}
                            }}
                            catch {{ }}
                        }};

                        Thread worker = new Thread(delegate()
                        {{
                            extractAction(uiReporter);
                            try
                            {{
                                if (progressForm.IsHandleCreated && !progressForm.IsDisposed)
                                    progressForm.BeginInvoke(new MethodInvoker(progressForm.Close));
                            }}
                            catch {{ }}
                        }});
                        worker.IsBackground = true;
                        progressForm.Shown += delegate {{ worker.Start(); }};
                        progressForm.ShowDialog();
                        worker.Join();
                    }}
                }}
                else
                {{
                    extractAction(null);
                }}

                if (extractError != null)
                    throw extractError;

                if (!EXTRACT_ONLY && !string.IsNullOrWhiteSpace(RUN_FILE))
                {{
                    launchedPid = ExecuteRunFile(targetDir);
                }}
            }}
            catch (Exception ex)
            {{
                if (!HIDDEN_RUN)
                    MessageBox.Show("Package processing failed: " + ex.Message,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                if (isTempExtraction)
                {{
                    TryDeleteDirectoryIfUnused(targetDir, true);
                }}
                return;
            }}
            finally
            {{
                TryDeleteDirectoryIfUnused(workTemp, true);
            }}

            if (isTempExtraction && !EXTRACT_ONLY)
            {{
                WaitAndCleanupTempFolder(targetDir, launchedPid);
            }}

            if (SELF_REMOVE)
            {{
                SelfDeleteExe();
            }}
        }}

        private static bool IsRunningAsAdministrator()
        {{
            try
            {{
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }}
            catch (Exception)
            {{
                return false;
            }}
        }}

        private static string BuildForwardedArguments()
        {{
            string[] args = Environment.GetCommandLineArgs();
            if (args == null || args.Length <= 1)
                return "";
            StringBuilder sb = new StringBuilder();
            for (int i = 1; i < args.Length; i++)
            {{
                if (i > 1)
                    sb.Append(" ");
                string arg = args[i] ?? "";
                StringBuilder escaped = new StringBuilder();
                int bs = 0;
                foreach (char c in arg)
                {{
                    if (c == '\\')
                    {{
                        bs++;
                    }}
                    else if (c == '"')
                    {{
                        escaped.Append('\\', bs * 2 + 1);
                        escaped.Append('"');
                        bs = 0;
                    }}
                    else
                    {{
                        if (bs > 0)
                        {{
                            escaped.Append('\\', bs);
                            bs = 0;
                        }}
                        escaped.Append(c);
                    }}
                }}
                if (bs > 0)
                    escaped.Append('\\', bs * 2);
                sb.Append("\"").Append(escaped.ToString()).Append("\"");
            }}
            return sb.ToString();
        }}

        private static void RelaunchPackageElevatedHidden()
        {{
            try
            {{
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Application.ExecutablePath;
                psi.Arguments = BuildForwardedArguments();
                psi.WorkingDirectory = Path.GetDirectoryName(Application.ExecutablePath);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process process = Process.Start(psi))
                {{
                }}
            }}
            catch (Win32Exception)
            {{
            }}
            catch (Exception)
            {{
            }}
        }}

        private static int ExecuteRunFile(string targetDir)
        {{
            string rawCmd = Environment.ExpandEnvironmentVariables(RUN_FILE.Trim().Replace("/", "\\"));
            string resolvedFile = "";
            string arguments = "";

            string strippedSourceRel = StripLeadingRelativeSlashes(rawCmd.Trim().Trim('"'));
            if (!string.IsNullOrEmpty(SOURCE_FOLDER_NAME) &&
                strippedSourceRel.StartsWith(SOURCE_FOLDER_NAME + "\\", StringComparison.OrdinalIgnoreCase))
            {{
                strippedSourceRel = StripLeadingRelativeSlashes(strippedSourceRel.Substring(SOURCE_FOLDER_NAME.Length + 1));
            }}

            string rawRelCandidate = StripLeadingRelativeSlashes(rawCmd);
            if (!Path.IsPathRooted(rawRelCandidate) && File.Exists(Path.Combine(targetDir, rawRelCandidate)))
            {{
                resolvedFile = Path.GetFullPath(Path.Combine(targetDir, rawRelCandidate));
            }}
            else if (!Path.IsPathRooted(strippedSourceRel) && File.Exists(Path.Combine(targetDir, strippedSourceRel)))
            {{
                resolvedFile = Path.GetFullPath(Path.Combine(targetDir, strippedSourceRel));
            }}
            else if (File.Exists(rawCmd))
            {{
                resolvedFile = Path.GetFullPath(rawCmd);
            }}
            else
            {{
                string candidatePath = rawCmd;
                if (rawCmd.StartsWith("\""))
                {{
                    int endQuote = rawCmd.IndexOf('\"', 1);
                    if (endQuote > 1)
                    {{
                        candidatePath = rawCmd.Substring(1, endQuote - 1);
                        arguments = rawCmd.Substring(endQuote + 1).Trim();
                    }}
                }}
                else
                {{
                    bool matchedByExt = false;
                    string firstExtCandidate = "";
                    string firstExtArgs = "";
                    string[] knownExtensions = new string[] {{ ".bat", ".cmd", ".ps1", ".exe", ".msi", ".reg" }};
                    foreach (string knownExtension in knownExtensions)
                    {{
                        int searchPos = 0;
                        while (searchPos < rawCmd.Length)
                        {{
                            int extAt = rawCmd.IndexOf(knownExtension, searchPos, StringComparison.OrdinalIgnoreCase);
                            if (extAt < 1) break;
                            int endAt = extAt + knownExtension.Length;
                            if (endAt == rawCmd.Length || Char.IsWhiteSpace(rawCmd[endAt]))
                            {{
                                string cand = rawCmd.Substring(0, endAt);
                                string candArgs = rawCmd.Substring(endAt).Trim();
                                if (string.IsNullOrEmpty(firstExtCandidate))
                                {{
                                    firstExtCandidate = cand;
                                    firstExtArgs = candArgs;
                                }}
                                string candRelCheck = StripLeadingRelativeSlashes(cand);
                                if (File.Exists(cand) ||
                                    (!Path.IsPathRooted(candRelCheck) && File.Exists(Path.Combine(targetDir, candRelCheck))))
                                {{
                                    candidatePath = cand;
                                    arguments = candArgs;
                                    matchedByExt = true;
                                }}
                            }}
                            searchPos = endAt;
                        }}
                    }}

                    if (!matchedByExt && !string.IsNullOrEmpty(firstExtCandidate))
                    {{
                        candidatePath = firstExtCandidate;
                        arguments = firstExtArgs;
                        matchedByExt = true;
                    }}

                    if (!matchedByExt)
                    {{
                        int spaceIdx = rawCmd.IndexOf(' ');
                        if (spaceIdx > 0)
                        {{
                            string firstPart = rawCmd.Substring(0, spaceIdx);
                            string firstRel = StripLeadingRelativeSlashes(firstPart);
                            if (File.Exists(firstPart) ||
                                (!Path.IsPathRooted(firstRel) && File.Exists(Path.Combine(targetDir, firstRel))) ||
                                firstPart.Contains("."))
                            {{
                                candidatePath = firstPart;
                                arguments = rawCmd.Substring(spaceIdx + 1).Trim();
                            }}
                        }}
                    }}
                }}

                string candidateRel = StripLeadingRelativeSlashes(candidatePath);
                string candidateStripped = candidateRel;
                if (!string.IsNullOrEmpty(SOURCE_FOLDER_NAME) &&
                    candidateStripped.StartsWith(SOURCE_FOLDER_NAME + "\\", StringComparison.OrdinalIgnoreCase))
                {{
                    candidateStripped = StripLeadingRelativeSlashes(candidateStripped.Substring(SOURCE_FOLDER_NAME.Length + 1));
                }}

                if (!Path.IsPathRooted(candidateRel) && File.Exists(Path.Combine(targetDir, candidateRel)))
                {{
                    resolvedFile = Path.GetFullPath(Path.Combine(targetDir, candidateRel));
                }}
                else if (!Path.IsPathRooted(candidateStripped) && File.Exists(Path.Combine(targetDir, candidateStripped)))
                {{
                    resolvedFile = Path.GetFullPath(Path.Combine(targetDir, candidateStripped));
                }}
                else if (File.Exists(candidatePath))
                {{
                    resolvedFile = Path.GetFullPath(candidatePath);
                }}
                else
                {{
                    string fileNameOnly = Path.GetFileName(candidatePath);
                    if (!string.IsNullOrEmpty(fileNameOnly) && !candidateRel.Contains("\\"))
                    {{
                        try
                        {{
                            string[] found = Directory.GetFiles(targetDir, fileNameOnly, SearchOption.AllDirectories);
                            if (found.Length == 1)
                                resolvedFile = Path.GetFullPath(found[0]);
                        }}
                        catch {{ }}
                    }}
                }}
            }}

            if (!string.IsNullOrEmpty(resolvedFile))
                resolvedFile = Path.GetFullPath(resolvedFile);
            string workDir = !string.IsNullOrEmpty(resolvedFile)
                ? Path.GetDirectoryName(resolvedFile)
                : Path.GetFullPath(targetDir);
            if (string.IsNullOrEmpty(workDir))
                workDir = Path.GetFullPath(targetDir);

            string ext = !string.IsNullOrEmpty(resolvedFile)
                ? Path.GetExtension(resolvedFile).ToLowerInvariant()
                : "";

            string fileNameToStart = "";
            string argsToStart = "";

            if (ext == ".reg" && !string.IsNullOrEmpty(resolvedFile))
            {{
                fileNameToStart = "regedit.exe";
                argsToStart = (HIDDEN_RUN ? "/s " : "") + "\"" + resolvedFile + "\"" +
                    (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                return RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
            }}

            if (ext == ".ps1")
            {{
                fileNameToStart = "powershell.exe";
                argsToStart = "-NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                    (HIDDEN_RUN ? "-WindowStyle Hidden " : "") +
                    "-File \"" + resolvedFile + "\"" +
                    (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                return RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
            }}

            if (ext == ".bat" || ext == ".cmd")
            {{
                fileNameToStart = "cmd.exe";
                argsToStart = "/D /S /C \"\"" + resolvedFile + "\"" +
                    (string.IsNullOrEmpty(arguments) ? "" : " " + arguments) + "\"";
                return RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
            }}

            if (ext == ".msi")
            {{
                fileNameToStart = "msiexec.exe";
                argsToStart = "/i \"" + resolvedFile + "\"" +
                    (HIDDEN_RUN ? " /qn /norestart" : "") +
                    (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                return RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
            }}

            if (!string.IsNullOrEmpty(resolvedFile) && File.Exists(resolvedFile))
            {{
                return RunNativeProcess(resolvedFile, arguments, workDir, HIDDEN_RUN);
            }}

            return RunNativeProcess("cmd.exe", "/D /S /C \"cd /d \"" + workDir + "\" && " + rawCmd + "\"", workDir, HIDDEN_RUN);
        }}

        private static string ResolveExecutableForCreateProcess(string fileName, string workDir)
        {{
            if (string.IsNullOrWhiteSpace(fileName))
                return null;
            if (Path.IsPathRooted(fileName) && File.Exists(fileName))
                return Path.GetFullPath(fileName);
            if (!string.IsNullOrEmpty(workDir))
            {{
                string localCand = Path.Combine(workDir, fileName);
                if (File.Exists(localCand))
                    return Path.GetFullPath(localCand);
            }}
            string sys32 = Environment.SystemDirectory;
            if (!string.IsNullOrEmpty(sys32))
            {{
                string sysCand = Path.Combine(sys32, fileName);
                if (File.Exists(sysCand))
                    return sysCand;
                if (string.Equals(fileName, "powershell.exe", StringComparison.OrdinalIgnoreCase))
                {{
                    string psCand = Path.Combine(sys32, @"WindowsPowerShell\v1.0\powershell.exe");
                    if (File.Exists(psCand))
                        return psCand;
                }}
            }}
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!string.IsNullOrEmpty(winDir))
            {{
                string winCand = Path.Combine(winDir, fileName);
                if (File.Exists(winCand))
                    return winCand;
            }}
            return null;
        }}

        private static bool TryRunHiddenNative(string fileName, string arguments, string workDir, out int pid)
        {{
            pid = 0;
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESHOWWINDOW;
            startup.wShowWindow = SW_HIDE;

            string resolvedExe = ResolveExecutableForCreateProcess(fileName, workDir);
            string cmdTarget = resolvedExe ?? fileName;
            string command = "\"" + cmdTarget + "\"" +
                (string.IsNullOrWhiteSpace(arguments) ? "" : " " + arguments);
            StringBuilder commandBuffer = new StringBuilder(command);
            PROCESS_INFORMATION processInfo;
            bool started = CreateProcessW(resolvedExe, commandBuffer, IntPtr.Zero, IntPtr.Zero,
                false, CREATE_NO_WINDOW, IntPtr.Zero, workDir, ref startup, out processInfo);
            if (!started)
                return false;

            pid = processInfo.dwProcessId;
            if (processInfo.hThread != IntPtr.Zero)
                CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero)
                CloseHandle(processInfo.hProcess);
            return true;
        }}

        private static int RunNativeProcess(string fileName, string arguments, string workDir, bool hidden)
        {{
            try
            {{
                int nativePid;
                if (hidden && TryRunHiddenNative(fileName, arguments, workDir, out nativePid))
                    return nativePid;

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = fileName;
                psi.Arguments = arguments;
                psi.WorkingDirectory = workDir;
                psi.UseShellExecute = hidden;
                psi.CreateNoWindow = false;
                psi.WindowStyle = hidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal;

                using (Process p = Process.Start(psi))
                {{
                    if (p != null)
                    {{
                        try {{ return p.Id; }} catch {{ }}
                    }}
                }}
            }}
            catch (Win32Exception ex)
            {{
                if (ex.NativeErrorCode == 740 && !hidden)
                {{
                    try
                    {{
                        ProcessStartInfo elevated = new ProcessStartInfo();
                        elevated.FileName = fileName;
                        elevated.Arguments = arguments;
                        elevated.WorkingDirectory = workDir;
                        elevated.UseShellExecute = true;
                        using (Process p = Process.Start(elevated))
                        {{
                            if (p != null)
                            {{
                                try {{ return p.Id; }} catch {{ }}
                            }}
                        }}
                    }}
                    catch (Exception)
                    {{
                    }}
                }}
                else if (!hidden)
                {{
                    MessageBox.Show("Failed to execute process: " + ex.Message,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }}
            }}
            catch (Exception ex)
            {{
                if (!hidden)
                    MessageBox.Show("Failed to execute process: " + ex.Message,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }}
            return 0;
        }}

        private static void WaitAndCleanupTempFolder(string tempDir, int pid)
        {{
            try
            {{
                if (string.IsNullOrEmpty(tempDir) || !Directory.Exists(tempDir))
                    return;

                if (pid > 0)
                {{
                    try
                    {{
                        using (Process child = Process.GetProcessById(pid))
                        {{
                            child.WaitForExit(6 * 3600 * 1000);
                        }}
                    }}
                    catch {{ }}
                }}
                else
                {{
                    Thread.Sleep(5000);
                }}

                for (int i = 0; i < 1800; i++)
                {{
                    if (!Directory.Exists(tempDir))
                        break;
                    if (TryDeleteDirectoryIfUnused(tempDir, true))
                        break;
                    Thread.Sleep(2000);
                }}
            }}
            catch {{ }}
        }}

        private static void SelfDeleteExe()
        {{
            try
            {{
                string exePath = Application.ExecutablePath;
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/D /C ping 127.0.0.1 -n 2 >nul & for /L %i in (1,1,15) do @(del /f /q \"" + exePath + "\" >nul 2>&1 & if exist \"" + exePath + "\" ping 127.0.0.1 -n 2 >nul)";
                psi.WorkingDirectory = Path.GetTempPath();
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process p = Process.Start(psi)) {{ }}
            }}
            catch {{ }}
        }}

        private static void ExtractOverlayArchive(string outPath, bool unscramble, Action<int> reportProgress)
        {{
            if (OVERLAY_ARCHIVE_SIZE < 32L)
                throw new InvalidDataException("No valid payload overlay is configured.");

            using (FileStream source = new FileStream(Application.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {{
                if (source.Length < OVERLAY_ARCHIVE_SIZE)
                    throw new InvalidDataException("The payload overlay is missing or incomplete.");

                long offset = source.Length - OVERLAY_ARCHIVE_SIZE;
                source.Seek(offset, SeekOrigin.Begin);

                if (!unscramble)
                {{
                    byte[] magic = new byte[] {{ 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }};
                    for (int i = 0; i < magic.Length; i++)
                        if (source.ReadByte() != magic[i])
                            throw new InvalidDataException("The 7z overlay signature is invalid.");
                    source.Seek(offset, SeekOrigin.Begin);
                }}

                byte[] key = Encoding.ASCII.GetBytes("byte_wrapper_secret_key");
                int klen = key.Length;
                int period = klen * 256;
                byte[] mask = new byte[period];
                if (unscramble)
                {{
                    for (int m = 0; m < period; m++)
                        mask[m] = (byte)(key[m % klen] ^ ((m & 0xFF) ^ 0xA5));
                }}

                long totalOffset = 0;
                int maskIdx = 0;
                int lastReported = -1;

                using (FileStream dest = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {{
                    long remaining = OVERLAY_ARCHIVE_SIZE;
                    byte[] buffer = new byte[65536];
                    while (remaining > 0L)
                    {{
                        int want = (int)Math.Min((long)buffer.Length, remaining);
                        int read = source.Read(buffer, 0, want);
                        if (read <= 0)
                            throw new EndOfStreamException("The payload overlay ended early.");

                        if (unscramble)
                        {{
                            for (int i = 0; i < read; i++)
                            {{
                                buffer[i] ^= mask[maskIdx];
                                if (++maskIdx == period)
                                    maskIdx = 0;
                            }}
                        }}

                        dest.Write(buffer, 0, read);
                        totalOffset += read;
                        remaining -= read;

                        if (reportProgress != null && OVERLAY_ARCHIVE_SIZE > 0)
                        {{
                            int pct = (int)((totalOffset * 50L) / OVERLAY_ARCHIVE_SIZE);
                            if (pct != lastReported)
                            {{
                                lastReported = pct;
                                reportProgress(pct);
                            }}
                        }}
                    }}
                }}
            }}
        }}

        private static void ExtractResourceIfExists(string resName, string outPath)
        {{
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
            {{
                if (s == null) return;
            }}
            ExtractResource(resName, outPath);
        }}

        private static void ExtractResource(string resName, string outPath)
        {{
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
            {{
                if (s == null)
                    throw new Exception("Resource not found: " + resName);

                byte[] buffer = new byte[65536];
                using (FileStream fs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {{
                    int read;
                    while ((read = s.Read(buffer, 0, buffer.Length)) > 0)
                    {{
                        fs.Write(buffer, 0, read);
                    }}
                }}
            }}
        }}

        private static Form CreateProgressForm(out ProgressBar pb, out Label lbl)
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

            lbl = new Label();
            lbl.Text = "Extracting package... 0%";
            lbl.AutoSize = false;
            lbl.Bounds = new Rectangle(16, 14, 300, 20);
            lbl.Font = new Font("Segoe UI", 9F, FontStyle.Regular);
            f.Controls.Add(lbl);

            pb = new ProgressBar();
            pb.Minimum = 0;
            pb.Maximum = 100;
            pb.Value = 0;
            pb.Style = ProgressBarStyle.Blocks;
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

        cs_code = build_cs_source(internal_7z_pw, expected_user_pw_hash)
        preview_pw = "***REDACTED***" if internal_7z_pw else ""
        preview_hash = "***REDACTED***" if expected_user_pw_hash else ""
        preview_cs_code = build_cs_source(preview_pw, preview_hash)

        cs_file = os.path.join(work_dir, "Stub.cs")
        with open(cs_file, "w", encoding="utf-8-sig") as f:
            f.write(cs_code)

        csc_cmd = [
            csc_path,
            "/nologo",
            "/target:winexe",
            "/optimize+",
            f"/out:{staging_exe}",
            f"/win32manifest:{manifest_path}",
            f'/resource:{os.path.join(work_dir, "7z.exe")},7z.exe',
        ]
        if has_dll:
            csc_cmd.append(f'/resource:{os.path.join(work_dir, "7z.dll")},7z.dll')

        icon_ico = self.cfg.get("icon_ico", "")
        if not (icon_ico and os.path.isfile(icon_ico)):
            icon_ico = get_app_icon_path()
        if icon_ico and os.path.isfile(icon_ico):
            csc_cmd.append(f"/win32icon:{icon_ico}")

        csc_cmd.append(cs_file)

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        proc = subprocess.Popen(
            csc_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creation_flags
        )
        with self._proc_lock:
            self._active_proc = proc

        if self._cancelled:
            self._terminate_process_tree(proc)
            with self._proc_lock:
                self._active_proc = None
            return False, "Canceled by user."

        try:
            stdout, stderr = proc.communicate(timeout=self.CSC_TIMEOUT_SEC)
        except subprocess.TimeoutExpired:
            self._terminate_process_tree(proc)
            return False, "C# Stub compiler (csc.exe) timed out."
        finally:
            with self._proc_lock:
                self._active_proc = None

        if self._cancelled:
            return False, "Canceled by user."

        if proc.returncode != 0 or not os.path.isfile(staging_exe):
            return False, f"C# Stub Compilation Error:\n{stdout}\n{stderr}"

        try:
            with open(staging_exe, 'ab') as output:
                output.write(b'\r\n' + _BW_SOURCE_START_MARKER + b'\r\n')
                output.write(preview_cs_code.encode('utf-8'))
                output.write(b'\r\n' + _BW_SOURCE_END_MARKER + b'\r\n')

            with open(payload_dat, "rb") as archive, open(staging_exe, "ab") as output:
                while True:
                    if self._cancelled:
                        raise RuntimeError("Canceled by user.")
                    buf = archive.read(1024 * 1024)
                    if not buf:
                        break
                    output.write(buf)

            if self._cancelled:
                raise RuntimeError("Canceled by user.")
        except Exception as exc:
            return False, str(exc)

        return True, staging_exe

    def run(self):
        work_dir = None
        staging_exe = ""
        success = False
        message = ""
        try:
            self.progress.emit(5)
            if self._cancelled:
                message = "Canceled by user."
                return

            seven_zip = self.find_7zip()
            if not seven_zip:
                message = "7-Zip (7z.exe) was not found! Please make sure 7-Zip is installed."
                return

            csc_path = self.find_csc()
            if not csc_path:
                message = "Windows .NET C# compiler (csc.exe) was not found!"
                return

            source_path = normalize_user_path(self.cfg["source"])
            if not source_path or not os.path.exists(source_path):
                message = f"Source Folder / File path does not exist:\n{source_path}"
                return

            out_dir = normalize_user_path(self.cfg["output"])
            if not out_dir:
                message = "Please specify a valid Output save path!"
                return

            run_script_path = ""
            if not self.cfg.get("extract_only", False):
                run_script_path = _resolve_unique_run_file_in_source(source_path, self.cfg.get("run_file", ""))
                if not run_script_path:
                    message = "Run File is missing or ambiguous inside Source Folder."
                    return

            target_exe = self.resolve_output_exe_path()

            # Prevent overwriting the source file or the selected Run File itself
            if os.path.isfile(source_path) and paths_refer_to_same_location(source_path, target_exe):
                message = "Output EXE path cannot be the same as the Source file!"
                return
            if run_script_path and paths_refer_to_same_location(run_script_path, target_exe):
                message = "Output EXE path cannot overwrite the selected Run File!"
                return

            # Unique temporary staging file in the output directory; existing target_exe is untouched on cancel/error
            staging_exe = os.path.join(
                os.path.dirname(target_exe),
                f".bw_staging_{os.getpid()}_{uuid.uuid4().hex[:8]}.tmp"
            )
            self.progress.emit(20)

            work_dir = tempfile.mkdtemp(prefix="byte_wrapper_build_")
            raw_7z = os.path.join(work_dir, "raw_package.7z")
            res_7z = self.build_7z_archive(seven_zip, source_path, raw_7z, target_exe, run_script_path)
            if self._cancelled:
                message = "Canceled by user."
                return
            if res_7z.returncode != 0:
                message = f"7-Zip Compression Error:\n{res_7z.stdout}"
                return

            self.progress.emit(60)
            scrambled_dat = os.path.join(work_dir, "payload.dat")
            payload_path, scrambled = self.prepare_payload(raw_7z, scrambled_dat)
            if self._cancelled:
                message = "Canceled by user."
                return
            self.progress.emit(75)

            ok, msg = self.compile_csharp_sfx(
                csc_path, work_dir, payload_path, scrambled, seven_zip, staging_exe
            )
            if not ok:
                message = msg
                return

            # Final post-packaging cancellation check before atomic commit
            if self._cancelled:
                message = "Canceled by user."
                return

            final_exe = self._commit_staging_exe(staging_exe, target_exe)
            staging_exe = ""
            self.output_exe_path = final_exe

            self.progress.emit(100)
            success = True
            message = f"Package successfully created at:\n{final_exe}"

        except Exception as e:
            message = f"Unexpected error: {str(e)}"
        finally:
            self._release_reservation_lock()
            if staging_exe and os.path.isfile(staging_exe):
                try:
                    os.unlink(staging_exe)
                except OSError:
                    pass
            if work_dir:
                _remove_build_directory_safely(work_dir)
            self.build_finished.emit(success, message)


# ==========================================
# MAIN APPLICATION WINDOW (BYTE WRAPPER GUI)
# ==========================================
class ByteWrapperWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Byte Wrapper")
        self.setFixedSize(380, 600)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAcceptDrops(True)
        self.drag_pos = QPoint()

        self.app_icon_path = get_app_icon_path()
        if not self.app_icon_path or not os.path.isfile(self.app_icon_path):
            fallback_ico = os.path.join(tempfile.gettempdir(), "byte_wrapper_default_box.ico")
            self._save_fallback_box_ico(fallback_ico)
            self.app_icon_path = fallback_ico

        self.current_icon_source = self.app_icon_path
        self.converted_ico_path = self.app_icon_path
        self._session_temp_icons: set[str] = set()

        cleanup_stale_temp_files(protected_paths={
            self.app_icon_path,
            self.current_icon_source,
            self.converted_ico_path,
        })

        dpr = max(1.0, self.devicePixelRatioF())
        self.default_gui_icon = load_crisp_gui_icon(self.app_icon_path, dpr)
        self.setWindowIcon(self.default_gui_icon)
        if QApplication.instance():
            QApplication.instance().setWindowIcon(self.default_gui_icon)

        self._user_edited_name = False
        self._tracked_source_path = ""
        self._importing_config = False
        self._close_pending = False
        self.worker: SFXBuilderWorker | None = None
        self.last_output_exe: str = ""
        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._on_blink_step)
        self._blink_step_count = 0

        self.init_ui()
        self.apply_styles()

    def _save_fallback_box_ico(self, out_ico: str):
        draw_default_sfx_icon(out_ico)

    def _register_session_icon(self, new_ico_path: str):
        """Track newly created temp ICO and clean up older unused session icons."""
        for old_ico in list(self._session_temp_icons):
            if old_ico != new_ico_path and old_ico != self.app_icon_path:
                if os.path.isfile(old_ico) and not _is_file_in_use(old_ico):
                    try:
                        os.unlink(old_ico)
                        self._session_temp_icons.discard(old_ico)
                    except OSError:
                        pass
        if new_ico_path and new_ico_path != self.app_icon_path:
            self._session_temp_icons.add(new_ico_path)

    def _apply_icon_to_button(self, ico_path: str):
        """Render the selected ICO onto the 24x24 button at exact physical screen DPI."""
        dpr = max(1.0, self.devicePixelRatioF())
        self.btn_icon.setIcon(load_crisp_gui_icon(ico_path, dpr))
        self.btn_icon.setIconSize(QSize(24, 24))

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(18, 14, 18, 18)
        main_layout.setSpacing(6)

        # --- HEADER ---
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 4)
        header_layout.setSpacing(10)

        self.logo_label = SFXDropLogo(self)
        self.logo_label.fileDropped.connect(self.inspect_sfx_file)
        logo_dpr = max(1.0, self.devicePixelRatioF())
        master_parcel = _render_parcel_canvas(1024, stroke_scale=1.08)
        logo_pix = pil_to_qpixmap(master_parcel, 36, logo_dpr)
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
        main_layout.addWidget(self._make_section_label("Source Folder"))
        self.inp_source = SmartLineEdit("Select or drag and drop file or folder...", mode="source", parent_win=self)
        self.inp_source.textChanged.connect(self.on_source_path_changed)
        main_layout.addWidget(self.inp_source)

        main_layout.addWidget(self._make_section_label("Extract To"))
        self.inp_extract = SmartLineEdit("Define extraction path...", mode="extract_to", parent_win=self)
        main_layout.addWidget(self.inp_extract)

        main_layout.addWidget(self._make_section_label("Run File"))
        self.inp_run = SmartLineEdit("Define run file path with parameters...", mode="run_file", parent_win=self)
        self.inp_run.textChanged.connect(self.on_run_file_changed)
        main_layout.addWidget(self.inp_run)

        main_layout.addWidget(self._make_section_label("Output"))
        self.inp_output = SmartLineEdit("Define save path...", mode="output", parent_win=self)
        main_layout.addWidget(self.inp_output)

        main_layout.addWidget(self._make_section_label("Name, Description & Version"))
        nd_layout = QHBoxLayout()
        nd_layout.setContentsMargins(0, 0, 0, 0)
        nd_layout.setSpacing(6)

        self.btn_icon = QPushButton()
        self.btn_icon.setObjectName("IconSelectBtn")
        self.btn_icon.setFixedSize(34, 34)
        self._apply_icon_to_button(self.app_icon_path)
        self.btn_icon.clicked.connect(self.open_icon_menu)
        self.btn_icon.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.btn_icon.customContextMenuRequested.connect(self.reset_icon_to_default)
        self.btn_icon.setToolTip('Left-click: icon options. Right-click: restore the default icon.')
        nd_layout.addWidget(self.btn_icon)

        self.inp_name = QLineEdit()
        self.inp_name.setPlaceholderText("Name...")
        self.inp_name.setFixedHeight(34)
        self.inp_name.textEdited.connect(self.on_name_manually_edited)
        nd_layout.addWidget(self.inp_name, stretch=4)

        self.inp_desc = QLineEdit()
        self.inp_desc.setPlaceholderText("Description...")
        self.inp_desc.setFixedHeight(34)
        nd_layout.addWidget(self.inp_desc, stretch=4)

        self.inp_version = QLineEdit()
        self.inp_version.setObjectName("VersionInput")
        self.inp_version.setPlaceholderText("Ver...")
        self.inp_version.setToolTip("Package file version (e.g. 1.0.0.0)")
        self.inp_version.setFixedSize(64, 34)
        ver_validator = QRegularExpressionValidator(
            QRegularExpression(r"^[0-9]{0,5}(\.[0-9]{0,5}){0,3}$"), self.inp_version
        )
        self.inp_version.setValidator(ver_validator)
        nd_layout.addWidget(self.inp_version)

        main_layout.addLayout(nd_layout)

        # --- SECOND SECTION: OPTIONS ---
        main_layout.addWidget(self._make_section_label("Options"))
        opt_grid = QGridLayout()
        opt_grid.setContentsMargins(0, 2, 0, 4)
        opt_grid.setHorizontalSpacing(8)
        opt_grid.setVerticalSpacing(10)
        opt_grid.setColumnStretch(0, 1)
        opt_grid.setColumnStretch(1, 1)
        opt_grid.setColumnStretch(2, 1)

        self.chk_admin = QCheckBox("Run As Admin")
        self.chk_hidden = QCheckBox("Hidden Run")
        self.chk_dont_replace = QCheckBox("Don't Replace")

        self.chk_extract_only = QCheckBox("Extract Only")
        self.chk_extract_only.toggled.connect(self.on_extract_only_toggled)
        self.chk_hidden.toggled.connect(self.on_hidden_run_toggled)
        self.chk_self_remove = QCheckBox("Self Remove")
        self.chk_progress_bar = QCheckBox("Progress Bar")

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
            self.inp_name, self.inp_desc, self.inp_version, self.inp_password
        ):
            field.textChanged.connect(self.reset_start_status)
        for option in all_checks:
            option.toggled.connect(self.reset_start_status)
        self._refresh_hidden_availability()

    def reset_start_status(self, *args):
        if self.worker is not None and self.worker.isRunning():
            return
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
                padding: 0px 8px;
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
            QLineEdit#VersionInput {
                padding: 0px 6px;
                font-size: 11px;
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

    # --- WINDOW DRAGGING & JSON CONFIG DROP ---
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                local_path = url.toLocalFile()
                if local_path and os.path.isfile(local_path) and local_path.lower().endswith(".json"):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                local_path = url.toLocalFile()
                if local_path and os.path.isfile(local_path) and local_path.lower().endswith(".json"):
                    self.import_config_from_path(normalize_user_path(local_path))
                    event.acceptProposedAction()
                    return
        event.ignore()

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
        ok, result = process_file(normalize_user_path(file_path))
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
        if checked and self.chk_hidden.isChecked():
            self.chk_hidden.setChecked(False)
        self.inp_run.setEnabled(not checked)
        if checked and not self._user_edited_name and not self.inp_name.text().strip():
            expanded = normalize_user_path(self.inp_source.text())
            if expanded and os.path.isdir(expanded):
                folder_stem = os.path.basename(expanded)
                if folder_stem:
                    self.inp_name.setText(folder_stem)
        self._refresh_hidden_availability()

    def on_hidden_run_toggled(self, checked: bool):
        if checked and self.chk_extract_only.isChecked():
            self.chk_extract_only.setChecked(False)
        self._refresh_hidden_availability()

    def _refresh_hidden_availability(self):
        extract_selected = self.chk_extract_only.isChecked()
        hidden_selected = self.chk_hidden.isChecked()

        self.chk_hidden.setEnabled(True)
        self.chk_extract_only.setEnabled(True)

        self._style_mutually_exclusive_option(self.chk_hidden, extract_selected)
        self._style_mutually_exclusive_option(self.chk_extract_only, hidden_selected)
        self.chk_hidden.setToolTip(
            "Click to switch from Extract Only to Hidden Run."
            if extract_selected else "Hide the initial run window. An application may open its own visible windows."
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

    @staticmethod
    def _normalize_source_path(path: str) -> str:
        """Compare folder selections independently of trailing separators, quotes, or letter case."""
        expanded = normalize_user_path(path)
        if not expanded:
            return ""
        return os.path.normcase(os.path.abspath(expanded))

    def _clear_source_dependent_fields(self):
        """A changed source invalidates the selected run command, name and custom icon."""
        self._user_edited_name = False
        self.inp_run.clear()
        self.inp_name.clear()
        self.reset_icon_to_default()

    def on_source_path_changed(self, path: str):
        """Handle manual edits and folder/file selections from the browse menu."""
        normalized = self._normalize_source_path(path)
        previous = self._tracked_source_path
        self._tracked_source_path = normalized
        if self._importing_config:
            return
        if normalized != previous:
            self._clear_source_dependent_fields()
            expanded = normalize_user_path(path)
            if expanded and os.path.isfile(expanded):
                ext = os.path.splitext(expanded)[1].lower()
                if ext in (".exe", ".msi", ".bat", ".cmd", ".ps1", ".reg"):
                    self.inp_run.setText(os.path.basename(expanded))
                    self.set_icon_from_run_file()
                else:
                    stem = os.path.splitext(os.path.basename(expanded))[0]
                    if stem and not self._user_edited_name:
                        self.inp_name.setText(stem)
            elif expanded and os.path.isdir(expanded) and self.chk_extract_only.isChecked():
                folder_stem = os.path.basename(expanded)
                if folder_stem and not self._user_edited_name:
                    self.inp_name.setText(folder_stem)

    def on_source_dropped(self, path: str):
        """On a new folder clear immediately; on the same folder recheck Run File."""
        previous = self._tracked_source_path
        normalized = self._normalize_source_path(path)
        self.inp_source.setText(path)
        if normalized == previous:
            self._revalidate_run_file_in_source()

    def _run_file_still_in_source(self) -> bool:
        """Only accept unambiguous files under the selected source, not PATH or unrelated folders."""
        return bool(_resolve_unique_run_file_in_source(self.inp_source.text(), self.inp_run.text()))

    def _revalidate_run_file_in_source(self):
        if self.inp_run.text().strip() and not self._run_file_still_in_source():
            self._clear_source_dependent_fields()

    def on_name_manually_edited(self, text: str):
        self._user_edited_name = bool(text.strip())

    def _extract_candidate_from_run_text(self, raw: str) -> str:
        cmd_part, _ = _split_command_and_args(raw, self.inp_source.text())
        return cmd_part

    def on_run_file_changed(self, text: str):
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
        self.current_icon_source = self.app_icon_path
        self.converted_ico_path = self.app_icon_path
        self._register_session_icon(self.app_icon_path)
        self._apply_icon_to_button(self.app_icon_path)
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

        unique_in_src = _resolve_unique_run_file_in_source(self.inp_source.text(), raw_run)
        if unique_in_src:
            return unique_in_src

        raw_cand = self._extract_candidate_from_run_text(raw_run)
        candidate = (
            normalize_user_path(raw_cand) if _is_unc_or_drive_abs(raw_cand)
            else _strip_relative_leading_slashes(raw_cand)
        )
        if candidate and os.path.isabs(candidate) and os.path.isfile(candidate):
            return candidate

        src = normalize_user_path(self.inp_source.text())
        if src and os.path.isfile(src):
            return src

        return ""

    def set_icon_from_run_file(self):
        target_file = self._resolve_run_file_for_icon()
        if not target_file:
            self.btn_icon.setToolTip("Could not locate an unambiguous icon from Run File or Source Folder.")
            return

        out_ico = create_unique_temp_icon_path()
        if extract_icon_from_file(target_file, out_ico) and os.path.isfile(out_ico):
            self.current_icon_source = target_file
            self.converted_ico_path = out_ico
            self._register_session_icon(out_ico)
            self._apply_icon_to_button(out_ico)
            self.reset_start_status()
        else:
            if os.path.isfile(out_ico):
                try:
                    os.unlink(out_ico)
                except OSError:
                    pass
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
        out_ico = create_unique_temp_icon_path()

        if ext in (".exe", ".ico"):
            success = extract_icon_from_file(file_path, out_ico)
        else:
            success = convert_image_to_ico(file_path, out_ico)

        if not success or not os.path.isfile(out_ico):
            if os.path.isfile(out_ico):
                try:
                    os.unlink(out_ico)
                except OSError:
                    pass
            self.btn_icon.setToolTip("Could not extract or convert the selected icon.")
            return

        self.current_icon_source = file_path
        self.converted_ico_path = out_ico
        self._register_session_icon(out_ico)
        self._apply_icon_to_button(out_ico)
        self.reset_start_status()

    # --- PASSWORD BLINK ANIMATION (5 TIMES ON IMPORT) ---
    def trigger_password_blink(self):
        self._blink_timer.stop()
        if not self.inp_password.text():
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Password)
            return
        self._blink_step_count = 0
        self.inp_password.setEchoMode(QLineEdit.EchoMode.Normal)
        self._blink_timer.start(180)

    def _on_blink_step(self):
        self._blink_step_count += 1
        if self._blink_step_count >= 10:
            self._blink_timer.stop()
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Password)
            return

        if self._blink_step_count % 2 == 1:
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Password)
        else:
            self.inp_password.setEchoMode(QLineEdit.EchoMode.Normal)

    def collect_config(self) -> dict:
        pw = self.inp_password.text()
        if not pw.strip():
            pw = ""
        return {
            "source": self.inp_source.text(),
            "extract_to": self.inp_extract.text(),
            "run_file": self.inp_run.text(),
            "output": self.inp_output.text(),
            "name": self.inp_name.text(),
            "description": self.inp_desc.text(),
            "version": self.inp_version.text(),
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
            "use_password": bool(pw),
            "password": pw,
        }

    def export_config(self):
        cfg = self.collect_config()
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

    @staticmethod
    def _validate_and_normalize_config(raw_cfg: object) -> dict:
        if not isinstance(raw_cfg, dict):
            raise ValueError("Configuration root must be a JSON object.")

        str_keys = ("source", "extract_to", "run_file", "output", "name", "description", "version", "icon_source", "password")
        bool_keys = (
            "run_as_admin", "hidden_run", "dont_replace", "extract_only",
            "self_remove", "progress_bar", "compress", "crypto", "instances"
        )

        validated = {}
        for k in str_keys:
            val = raw_cfg.get(k, "")
            if val is None:
                val = ""
            if not isinstance(val, str):
                raise TypeError(f"Field '{k}' must be a string.")
            validated[k] = val

        for k in bool_keys:
            val = raw_cfg.get(k, False)
            if not isinstance(val, bool):
                raise TypeError(f"Field '{k}' must be a boolean.")
            validated[k] = val

        if validated["extract_only"] and validated["hidden_run"]:
            validated["hidden_run"] = False

        validated["decrypted_password"] = decrypt_password_from_import(validated["password"])
        return validated

    def import_config_from_path(self, open_path: str):
        if not open_path:
            return
        try:
            with open(open_path, "r", encoding="utf-8") as f:
                raw_cfg = json.load(f)

            cfg = self._validate_and_normalize_config(raw_cfg)

            self._importing_config = True
            self._user_edited_name = bool(cfg["name"].strip())
            self._tracked_source_path = self._normalize_source_path(cfg["source"])
            self.inp_source.setText(cfg["source"])
            self.inp_extract.setText(cfg["extract_to"])
            self.inp_run.setText(cfg["run_file"])
            self.inp_output.setText(cfg["output"])
            self.inp_name.setText(cfg["name"])
            self.inp_desc.setText(cfg["description"])
            self.inp_version.setText(cfg["version"])

            if not cfg["name"].strip() and cfg["run_file"].strip():
                self.on_run_file_changed(cfg["run_file"])

            self.chk_admin.setChecked(cfg["run_as_admin"])
            self.chk_hidden.setChecked(cfg["hidden_run"])
            self.chk_dont_replace.setChecked(cfg["dont_replace"])
            self.chk_extract_only.setChecked(cfg["extract_only"])
            self.chk_self_remove.setChecked(cfg["self_remove"])
            self.chk_progress_bar.setChecked(cfg["progress_bar"])
            self.chk_compress.setChecked(cfg["compress"])
            self.chk_crypto.setChecked(cfg["crypto"])
            self.chk_instances.setChecked(cfg["instances"])
            self._refresh_hidden_availability()

            decrypted_pw = cfg["decrypted_password"]
            self.inp_password.setText(decrypted_pw)
            if decrypted_pw:
                self.trigger_password_blink()

            icon_src = normalize_user_path(cfg["icon_source"])
            icon_loaded = False
            if icon_src and os.path.isfile(icon_src):
                out_ico = create_unique_temp_icon_path()
                if icon_src.lower().endswith((".exe", ".ico")):
                    ok_ico = extract_icon_from_file(icon_src, out_ico)
                else:
                    ok_ico = convert_image_to_ico(icon_src, out_ico)
                if ok_ico and os.path.isfile(out_ico):
                    self.current_icon_source = icon_src
                    self.converted_ico_path = out_ico
                    self._register_session_icon(out_ico)
                    self._apply_icon_to_button(out_ico)
                    icon_loaded = True
                elif os.path.isfile(out_ico):
                    try:
                        os.unlink(out_ico)
                    except OSError:
                        pass

            if not icon_loaded:
                self.current_icon_source = self.app_icon_path
                self.converted_ico_path = self.app_icon_path
                self._register_session_icon(self.app_icon_path)
                self._apply_icon_to_button(self.app_icon_path)

            self.btn_import.setToolTip("")
        except Exception as e:
            self.btn_import.setToolTip(f"Failed to import configuration: {e}")
        finally:
            self._importing_config = False

    def import_config(self):
        open_path, _ = QFileDialog.getOpenFileName(
            self, "Import Configuration Script", "", "JSON Script (*.json)"
        )
        if open_path:
            self.import_config_from_path(open_path)

    def _source_run_file_path(self) -> str:
        """Resolve a selected run file inside Source Folder unambiguously."""
        return _resolve_unique_run_file_in_source(self.inp_source.text(), self.inp_run.text())

    def open_completed_output_folder(self):
        """Open the output directory (selecting the built EXE on Windows) when 'Completed' is clicked."""
        target_exe = self.last_output_exe
        if target_exe and os.path.isfile(target_exe):
            if os.name == "nt":
                try:
                    subprocess.Popen(["explorer.exe", f"/select,{os.path.normpath(target_exe)}"])
                    return
                except OSError:
                    pass
            open_with_default_viewer(os.path.dirname(target_exe))
            return

        raw_out = normalize_user_path(self.inp_output.text())
        if raw_out and os.path.isdir(raw_out):
            open_with_default_viewer(raw_out)

    def start_process(self):
        # 1. If a build is currently running, allow the user to cancel it
        if self.worker is not None and self.worker.isRunning():
            self.btn_start.setEnabled(False)
            self.btn_start.setText("Canceling...")
            self.worker.cancel()
            return

        # 2. If build is in 'Completed' state, open the output folder
        if self.btn_start.text() == "Completed":
            self.open_completed_output_folder()
            return

        # 3. Normalize & validate inputs once before starting a new build
        cfg = self.collect_config()
        norm_source = normalize_user_path(cfg["source"])
        norm_output = normalize_user_path(cfg["output"])
        extract_raw = cfg["extract_to"].strip().strip('"')
        name_raw = cfg["name"].strip()
        ver_raw = cfg["version"].strip()

        if not norm_source or not os.path.exists(norm_source) or not is_valid_output_directory_path(norm_output):
            self.btn_start.setText("Failed")
            self.btn_start.setToolTip("")
            return

        # Store normalized source and output so Worker uses the exact same paths
        cfg["source"] = norm_source
        cfg["output"] = norm_output

        # Version format check (strict ASCII digits, rejects 'abc123' and '1.²')
        if not is_valid_version_string(ver_raw):
            self.btn_start.setText("Failed")
            self.btn_start.setToolTip("")
            return

        # Windows reserved device names & illegal characters check (CON, CON.foo.bar, NUL, PRN, LPT1.log.more, etc.)
        pkg_check_name = name_raw[:-4] if name_raw.lower().endswith(".exe") else name_raw
        if (is_windows_reserved_name(pkg_check_name)
                or path_has_reserved_or_invalid_component(extract_raw)):
            self.btn_start.setText("Failed")
            self.btn_start.setToolTip("")
            return

        # Run File existence & unambiguous validity check when not in 'Extract Only' mode
        run_script_path = ""
        if not cfg["extract_only"]:
            run_script_path = self._source_run_file_path()
            if not cfg["run_file"].strip() or not run_script_path:
                self.btn_start.setText("Failed")
                self.btn_start.setToolTip("")
                return

        # Prevent source-file / run-file vs output-EXE collision
        safe_base_name = SFXBuilderWorker.sanitize_package_base_name(name_raw)
        planned_exe = os.path.join(norm_output, f"{safe_base_name}.exe")

        if os.path.isfile(norm_source) and paths_refer_to_same_location(norm_source, planned_exe):
            if not (cfg["dont_replace"] and os.path.exists(planned_exe)):
                self.btn_start.setText("Failed")
                self.btn_start.setToolTip("")
                return

        if run_script_path and paths_refer_to_same_location(run_script_path, planned_exe):
            if not (cfg["dont_replace"] and os.path.exists(planned_exe)):
                self.btn_start.setText("Failed")
                self.btn_start.setToolTip("")
                return

        cfg["self_elevating_run_file"] = _looks_like_self_elevating_script(run_script_path)
        self.btn_start.setEnabled(True)
        self.btn_start.setText("Cancel")
        self.btn_start.setToolTip("")
        self.progress_bar.setValue(0)

        self.worker = SFXBuilderWorker(cfg)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.build_finished.connect(self.on_process_finished)
        self.worker.finished.connect(self.on_worker_thread_finished)
        self.worker.start()

    def on_process_finished(self, success: bool, _message: str):
        if self._close_pending:
            return

        self.btn_start.setEnabled(True)
        self.btn_start.setToolTip("")
        was_cancelled = self.worker is not None and self.worker._cancelled
        if was_cancelled:
            self.progress_bar.setValue(0)
            self.btn_start.setText("Canceled")
            return

        if success:
            if self.worker is not None:
                self.last_output_exe = self.worker.output_exe_path
            self.btn_start.setText("Completed")
        else:
            self.progress_bar.setValue(0)
            self.btn_start.setText("Failed")

    def on_worker_thread_finished(self):
        """Invoked by QThread.finished after the OS thread has completely exited."""
        if self._close_pending:
            self.close()

    def closeEvent(self, event):
        """Defer window close until QThread.finished fires so the worker never outlives the window."""
        if self.worker is not None and self.worker.isRunning():
            self._close_pending = True
            self.btn_start.setEnabled(False)
            self.btn_start.setText("Canceling...")
            self.worker.cancel()
            event.ignore()
            return

        for ico_path in list(self._session_temp_icons):
            if ico_path != self.app_icon_path and os.path.isfile(ico_path) and not _is_file_in_use(ico_path):
                try:
                    os.unlink(ico_path)
                except OSError:
                    pass
        self._session_temp_icons.clear()
        cleanup_stale_temp_files(protected_paths={self.app_icon_path})
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = ByteWrapperWindow()
    win.show()
    sys.exit(app.exec())