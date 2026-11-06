import os
import re
import sys
import json
import uuid
import struct
import base64
import gzip
import zlib
import hashlib
import shutil
import ctypes
from ctypes import wintypes
import subprocess
import tempfile
import threading
import io
from datetime import datetime
from xml.sax.saxutils import escape as xml_escape

# Support #
# Update Python # py -m pip install --upgrade pip
# Install Components # py -m pip install PyQt6 Pillow pillow-jxl-plugin pyinstaller
# Compile # py -m PyInstaller --noconfirm --clean --onefile --windowed --name "Byte Wrapper" --icon "Byte.ICO" --collect-all pillow_jxl "Byte Wrapper - Final.py"

# ==============================================================================
# 1. GLOBAL COMMANDS, CONSTANTS & CORE UTILITIES
# ==============================================================================
try:
    hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 0)
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ByteWrapper.SFXConstructor")
except Exception:
    pass

from PyQt6.QtCore import (
    Qt, QPoint, QUrl, QEvent, QPropertyAnimation, QEasingCurve, QThread, pyqtSignal, QSize, QTimer, QRegularExpression
)
from PyQt6.QtGui import (
    QIcon, QImage, QPixmap, QDragEnterEvent, QDropEvent, QRegularExpressionValidator, QDesktopServices, QCursor
)
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QProgressBar,
    QFileDialog, QMenu, QMessageBox, QDialog
)

from PIL import Image, ImageDraw
try:
    import pillow_jxl  # Support for .jxl files
except ImportError:
    pass

_BW_SOURCE_START_MARKER = b";!@ByteWrapperSource@UTF-8!"
_BW_SOURCE_END_MARKER = b";!@ByteWrapperSourceEnd@!"
_BW_PACKED_SOURCE_START_MARKER = b";!@ByteWrapperSource@GZIP64!"
_BW_PACKED_SOURCE_END_MARKER = b";!@ByteWrapperSourceGzipEnd@!"
_BW_ZLIB_SOURCE_START_MARKER = b";!@ByteWrapperSource@ZLIB!"
_BW_ZLIB_SOURCE_END_MARKER = b";!@ByteWrapperSourceZlibEnd@!"
_BW_HEADER_SCAN_LIMIT = 12 * 1024 * 1024
_IO_BUFFER_SIZE = 16 * 1024 * 1024
_BCJ_X86_RE = re.compile(rb"[\xe8\xe9].{4}", re.DOTALL)

_RUNNABLE_EXTS = (".exe", ".msi", ".bat", ".cmd", ".ps1", ".reg", ".vbs", ".js", ".wsf", ".msc", ".com", ".scr")
_DIRECT_ICON_EXTS = (".ico", ".png", ".jpg", ".jpeg", ".jxl")
_EXECUTABLE_EXT_RE = re.compile(
    r"\.(?:bat|cmd|ps1|exe|msi|reg|vbs|js|wsf|msc|com|scr)(?=\s|$)",
    re.IGNORECASE,
)
_SELF_ELEVATE_RE = re.compile(
    r"\bstart-process\b[^\r\n]*\s-verb\s+['\"]?runas\b"
    r"|\bshell\.application\b[\s\S]{0,240}?\bshellexecute\b[\s\S]{0,240}?['\"]runas['\"]"
    r"|^.*\b(?:fltmc|net\s+session)\b[^\r\n]*\|\|[^\r\n]*\bstart\b"
    r"|\bmshta\b[^\r\n]*\brunas\b",
    re.IGNORECASE | re.MULTILINE,
)
_ADMIN_PROBE_RE = re.compile(r"\b(?:fltmc|net\s+session|whoami\s+/groups)\b", re.IGNORECASE)
_RUNAS_RE = re.compile(r"runas", re.IGNORECASE)
_COMMENT_LINE_RE = re.compile(r"^\s*(?:rem\s|::|#)", re.IGNORECASE)
_INVALID_FILENAME_CHARS_RE = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
_RESERVED_WIN_NAMES_RE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$",
    re.IGNORECASE,
)
_INVALID_PATH_CHARS = frozenset('*?"<>|')
_PCT_RE = re.compile(rb"(?:^|[\r\n\x08])\s*(\d{1,3})%(?=\s|$)")

_CFG_STR_KEYS = (
    "source", "extract_to", "run_file", "output",
    "name", "description", "version", "icon_source", "password",
    "shortcut_icon_source", "shortcut_name", "shortcut_path", "shortcut_run_file",
)
_CFG_BOOL_KEYS = (
    "run_as_admin", "hidden_run", "dont_replace", "extract_only",
    "self_remove", "progress_bar", "compress", "crypto", "instances",
)

SECRET_EXPORT_KEY = b"ByteWrapper_Config_Cipher_Key"
_CACHED_TOOL_PATHS: dict[str, str] = {}
_CACHED_RUNTIME_PACKS: dict[tuple[str, int, int], tuple[str, bytes]] = {}
_CACHED_AES_SUPPORT: dict[tuple[str, int, int], bool] = {}
_SINGLE_INSTANCE_MUTEX = None

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ENUMRESNAMEPROCW = ctypes.WINFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t
)
_KERNEL32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, ctypes.c_wchar_p]
_KERNEL32.CreateMutexW.restype = wintypes.HANDLE
_KERNEL32.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
_KERNEL32.LoadLibraryExW.restype = ctypes.c_void_p
_KERNEL32.FreeLibrary.argtypes = [ctypes.c_void_p]
_KERNEL32.FreeLibrary.restype = wintypes.BOOL
_KERNEL32.EnumResourceNamesW.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, _ENUMRESNAMEPROCW, ctypes.c_ssize_t
]
_KERNEL32.EnumResourceNamesW.restype = wintypes.BOOL
_KERNEL32.FindResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_KERNEL32.FindResourceW.restype = ctypes.c_void_p
_KERNEL32.LoadResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_KERNEL32.LoadResource.restype = ctypes.c_void_p
_KERNEL32.LockResource.argtypes = [ctypes.c_void_p]
_KERNEL32.LockResource.restype = ctypes.c_void_p
_KERNEL32.SizeofResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_KERNEL32.SizeofResource.restype = ctypes.c_uint32

_SHELL32 = ctypes.WinDLL("shell32", use_last_error=True)
_SHELL32.PickIconDlg.argtypes = [
    wintypes.HWND, ctypes.c_wchar_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_int)
]
_SHELL32.PickIconDlg.restype = ctypes.c_int


def _acquire_single_instance_lock() -> bool:
    """Ensure only a single instance of Byte Wrapper runs at a time."""
    global _SINGLE_INSTANCE_MUTEX
    _SINGLE_INSTANCE_MUTEX = _KERNEL32.CreateMutexW(
        None, False, "Local\\ByteWrapper_SFXConstructor_SingleInstance"
    )
    if not _SINGLE_INSTANCE_MUTEX or ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        try:
            existing_hwnd = ctypes.windll.user32.FindWindowW(None, "Byte Wrapper")
            if existing_hwnd:
                if ctypes.windll.user32.IsIconic(existing_hwnd):
                    ctypes.windll.user32.ShowWindow(existing_hwnd, 9)  # SW_RESTORE
                ctypes.windll.user32.SetForegroundWindow(existing_hwnd)
        except Exception:
            pass
        return False
    return True


def expand_path(raw_path: str, resolve_abs: bool = False) -> str:
    cleaned = os.path.expandvars((raw_path or "").strip().strip('"').strip("'"))
    if not cleaned:
        return ""
    if len(cleaned) == 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        cleaned += "\\"
    return os.path.abspath(cleaned) if resolve_abs else os.path.normpath(cleaned)


def _has_invalid_path_chars(path_str: str) -> bool:
    if not path_str:
        return True
    _, tail = os.path.splitdrive(path_str)
    return ":" in tail or any(c in _INVALID_PATH_CHARS or ord(c) < 32 for c in path_str)


def _validate_package_name(raw_name: str) -> str | None:
    """Validate package name and return clean base name without .exe, or None if invalid."""
    if not raw_name:
        return "Byte Wrapper"
    if _INVALID_FILENAME_CHARS_RE.search(raw_name):
        return None
    name = raw_name.strip()
    if not name:
        return None
    if name.lower().endswith(".exe"):
        name = name[:-4]
    name = name.strip().rstrip(". ")
    if not name or _RESERVED_WIN_NAMES_RE.match(name):
        return None
    return name


def _derive_auto_name_from_path(path_str: str, strip_ext: bool = True) -> str:
    base = os.path.basename(path_str.replace("/", "\\"))
    stem = (os.path.splitext(base)[0] if strip_ext else base).strip()
    return (_validate_package_name(stem) or "") if stem else ""


def _relpath_if_within(path: str, directory: str) -> str:
    """Return relative path when path is inside directory ('.' if identical), else empty string."""
    if not path or not directory:
        return ""
    try:
        path_real = os.path.realpath(path)
        dir_real = os.path.realpath(directory)
        path_nc = os.path.normcase(path_real)
        dir_nc = os.path.normcase(dir_real)
        if os.path.commonpath((path_nc, dir_nc)) == dir_nc:
            return os.path.relpath(path_real, dir_real)
    except (OSError, ValueError):
        pass
    return ""



def _has_matching_url(event, allowed_exts: tuple[str, ...] = ()) -> bool:
    """Fast, zero-disk-I/O check used during dragEnterEvent."""
    if not event.mimeData().hasUrls():
        return False
    for url in event.mimeData().urls():
        path = url.toLocalFile()
        if path and (not allowed_exts or path.lower().endswith(allowed_exts)):
            return True
    return False


def _first_dropped_path(event, allowed_exts: tuple[str, ...] = ()) -> str:
    """Resolve the first valid local path on dropEvent."""
    if not event.mimeData().hasUrls():
        return ""
    for url in event.mimeData().urls():
        path = url.toLocalFile()
        if not path:
            continue
        if not allowed_exts or (os.path.isfile(path) and path.lower().endswith(allowed_exts)):
            return expand_path(path)
    return ""


def _parse_pe_version(raw_ver: str) -> tuple[str, str] | None:
    """Validate and normalize version into (4-part PE version, informational version), or None if invalid."""
    cleaned = (raw_ver or "").strip()
    if not cleaned:
        return "1.0.0.0", "1.0.0.0"
    parts = cleaned.split(".")
    if len(parts) > 4:
        return None
    normalized: list[str] = []
    for part in parts:
        if not (1 <= len(part) <= 5 and part.isascii() and part.isdigit()):
            return None
        val = int(part)
        if val > 65534:
            return None
        normalized.append(str(val))
    while len(normalized) < 4:
        normalized.append("0")
    return ".".join(normalized), cleaned


def _validate_metadata_fields(
    raw_name: str, raw_desc: str, raw_ver: str
) -> tuple[str, str, tuple[str, str]]:
    """Validate package name, description, and version in a single place."""
    base_name = _validate_package_name(raw_name)
    if base_name is None:
        raise ValueError(
            "Package name contains invalid characters or is a reserved Windows file name."
        )
    desc_clean = (raw_desc or "").strip()
    if _INVALID_FILENAME_CHARS_RE.search(desc_clean):
        raise ValueError("Description contains invalid characters.")
    parsed_ver = _parse_pe_version(raw_ver)
    if parsed_ver is None:
        raise ValueError("Version must be 1 to 4 numbers (0-65534) separated by dots.")
    return base_name, desc_clean, parsed_ver


def _validate_password_input(pw: str) -> str:
    if pw and not pw.strip():
        raise ValueError("Password cannot contain only whitespace.")
    return pw


def _remove_temporary_path(path: str, is_dir: bool = False):
    """Best-effort cleanup of a single temporary output."""
    if not path:
        return
    try:
        if is_dir:
            if os.path.isdir(path):
                shutil.rmtree(path)
        elif os.path.lexists(path):
            os.unlink(path)
    except OSError:
        pass


def cleanup_temp_files_now(output_dir: str = ""):
    """Cleanup leftover Byte Wrapper preview files, build folders, and staging files."""
    try:
        with os.scandir(tempfile.gettempdir()) as entries:
            for entry in entries:
                name_l = entry.name.lower()
                if name_l.startswith("byte_wrapper_code_") and name_l.endswith(".txt"):
                    _remove_temporary_path(entry.path, False)
                elif name_l.startswith("byte_wrapper_build_") and entry.is_dir(follow_symlinks=False):
                    _remove_temporary_path(entry.path, True)
    except OSError:
        pass

    norm_out = expand_path(output_dir)
    if norm_out and os.path.isdir(norm_out):
        try:
            with os.scandir(norm_out) as entries:
                for entry in entries:
                    name_l = entry.name.lower()
                    if (name_l.startswith((".bw_staging_", ".bw_cfg_"))
                            and name_l.endswith(".tmp")):
                        _remove_temporary_path(entry.path, False)
        except OSError:
            pass


def _get_optimal_runtime_pack(file_path: str) -> tuple[str, bytes]:
    """Pick the smallest supported encoding: raw, Deflate, or PE BCJ+Deflate."""
    st = os.stat(file_path)
    cache_key = (os.path.normcase(os.path.abspath(file_path)), st.st_mtime_ns, st.st_size)
    cached = _CACHED_RUNTIME_PACKS.get(cache_key)
    if cached is not None:
        _CACHED_RUNTIME_PACKS.pop(cache_key)
        _CACHED_RUNTIME_PACKS[cache_key] = cached
        return cached

    with open(file_path, "rb") as source:
        original = source.read()
    best_mode, best_data = "raw", original

    def deflate(data: bytes) -> bytes:
        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS, memLevel=9)
        return compressor.compress(data) + compressor.flush()

    packed = deflate(original)
    if len(packed) < len(best_data):
        best_mode, best_data = "def", packed

    # BCJ only applies to PE files; keep the same reversible transform as the C# stub.
    if len(original) <= 32 * 1024 * 1024 and original[:2] == b"MZ":
        filtered = bytearray(original)
        for match in _BCJ_X86_RE.finditer(original):
            pos = match.start()
            value = int.from_bytes(original[pos + 1:pos + 5], "little")
            filtered[pos + 1:pos + 5] = ((value + pos) & 0xFFFFFFFF).to_bytes(4, "little")
        packed_bcj = deflate(filtered)
        if len(packed_bcj) < len(best_data):
            best_mode, best_data = "bcj", packed_bcj

    result = best_mode, best_data
    # Prevent large embedded runtimes from remaining resident for the app lifetime.
    if len(best_data) <= 16 * 1024 * 1024:
        while _CACHED_RUNTIME_PACKS and (
            len(_CACHED_RUNTIME_PACKS) >= 4 or
            sum(len(item[1]) for item in _CACHED_RUNTIME_PACKS.values()) + len(best_data) > 32 * 1024 * 1024
        ):
            _CACHED_RUNTIME_PACKS.pop(next(iter(_CACHED_RUNTIME_PACKS)))
        _CACHED_RUNTIME_PACKS[cache_key] = result
    return result


def process_file(file_path):
    """Open 7-Zip SFX configs or Byte Wrapper's embedded C# source in the default viewer."""
    cleanup_temp_files_now()
    sources = (
        (b';!@Install@!UTF-8!', b';!@InstallEnd@!', '7-Zip SFX config', False),
        (b';!@Install@!', b';!@InstallEnd@!', '7-Zip SFX config', False),
        (_BW_SOURCE_START_MARKER, _BW_SOURCE_END_MARKER, 'Byte Wrapper generated C# source', False),
        (_BW_PACKED_SOURCE_START_MARKER, _BW_PACKED_SOURCE_END_MARKER, 'Byte Wrapper generated C# source', "gzip64"),
        (_BW_ZLIB_SOURCE_START_MARKER, _BW_ZLIB_SOURCE_END_MARKER, 'Byte Wrapper generated C# source', "zlib"),
    )
    try:
        if not os.path.isfile(file_path):
            return False, 'The selected EXE / SFX file does not exist.'

        with open(file_path, 'rb') as f:
            data = f.read(_BW_HEADER_SCAN_LIMIT)
        if not data:
            return False, 'The selected file is empty.'

        content = None
        source_type = ''
        for start_marker, end_marker, description, packed in sources:
            start_idx = data.find(start_marker)
            if start_idx < 0:
                continue
            end_idx = data.find(end_marker, start_idx + len(start_marker))
            if end_idx < 0 or end_idx - start_idx > 2 * 1024 * 1024:
                continue
            if packed == "gzip64":
                payload = data[start_idx + len(start_marker):end_idx].strip()
                content = gzip.decompress(base64.b64decode(payload, validate=True)).decode('utf-8-sig')
            elif packed == "zlib":
                payload = data[start_idx + len(start_marker):end_idx]
                if payload.startswith(b"\r\n"):
                    payload = payload[2:]
                if payload.endswith(b"\r\n"):
                    payload = payload[:-2]
                content = zlib.decompress(payload).decode('utf-8-sig')
            else:
                raw_source = data[start_idx:end_idx + len(end_marker)]
                if start_marker == _BW_SOURCE_START_MARKER:
                    # Old Byte Wrapper variants used UTF-8 markers with
                    # a ZLIB:\n prefix and binary zlib data inside.
                    inner = data[start_idx + len(start_marker):end_idx]
                    if inner.startswith(b"\r\n"):
                        inner = inner[2:]
                    if inner.startswith(b"ZLIB:\n"):
                        packed = inner[len(b"ZLIB:\n"):]
                        if packed.endswith(b"\r\n"):
                            packed = packed[:-2]
                        content = (
                            start_marker + b"\r\n" + zlib.decompress(packed)
                            + b"\r\n" + end_marker
                        ).decode('utf-8-sig', errors='replace')
                if content is None:
                    content = raw_source.decode('utf-8-sig', errors='replace')
            source_type = description
            break

        if content is None:
            return False, ('No supported 7-Zip SFX configuration or Byte Wrapper source was found. '
                           'Protected or normal EXE files do not contain readable source code.')

        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8-sig', suffix='.txt', prefix='byte_wrapper_code_', delete=False
        ) as output:
            output.write(f'File: {os.path.basename(file_path)}\n')
            output.write(f'Type: {source_type}\n')
            output.write('View only: saving this text will not modify the EXE.\n')
            output.write('=' * 60 + '\n\n')
            output.write(content)
            output_file = output.name

        os.startfile(os.path.normpath(output_file))
        return True, output_file
    except Exception as exc:
        return False, f'Unable to open SFX code: {exc}'


def _xor_cipher(data: bytes) -> bytes:
    return bytes(b ^ SECRET_EXPORT_KEY[i % len(SECRET_EXPORT_KEY)] for i, b in enumerate(data))


def encrypt_password_for_export(plain_text: str) -> str:
    if not plain_text:
        return ""
    return "ENC:" + base64.urlsafe_b64encode(_xor_cipher(plain_text.encode("utf-8"))).decode("ascii")


def decrypt_password_from_import(cipher_text: str) -> str:
    if not isinstance(cipher_text, str):
        raise ValueError("Password value must be a string.")
    if not cipher_text:
        return ""
    if cipher_text.startswith("ENC:"):
        payload = cipher_text[4:]
        if not payload:
            raise ValueError("Encrypted password data is empty.")
        try:
            raw_bytes = base64.urlsafe_b64decode(payload.encode("ascii"))
            if base64.urlsafe_b64encode(raw_bytes).decode("ascii") != payload:
                raise ValueError("Invalid base64 password payload.")
            plain = _xor_cipher(raw_bytes).decode("utf-8")
        except Exception as exc:
            raise ValueError("Corrupted encrypted password data.") from exc
        return _validate_password_input(plain)
    return _validate_password_input(cipher_text)


def _split_command_and_args(raw: str) -> tuple[str, str]:
    """Separate Run File input into (file_path, parameters_string)."""
    s = (raw or "").strip()
    if not s:
        return "", ""
    if s.startswith('"'):
        end_q = s.find('"', 1)
        return (s[1:end_q].strip(), s[end_q + 1:].strip()) if end_q > 1 else (s.strip('"').strip(), "")

    m = _EXECUTABLE_EXT_RE.search(s)
    if m:
        return s[:m.end()].strip(), s[m.end():].strip()

    parts = s.split(None, 1)
    return (parts[0], "") if len(parts) == 1 else (parts[0], parts[1].strip())


def _resolve_run_file(
    source_path: str,
    cmd_part: str,
    source_resolved: bool = False,
    source_kind: str = "",
) -> tuple[str, str]:
    """Locate run file in source and compute its package-relative target in a single pass."""
    src = source_path if source_resolved else expand_path(source_path, resolve_abs=True)
    if not src:
        return "", cmd_part.replace("/", "\\")

    if not source_kind:
        if os.path.isdir(src):
            source_kind = "dir"
        elif os.path.isfile(src):
            source_kind = "file"

    resolved_run_path = ""
    cand = expand_path(cmd_part) if cmd_part else ""
    cand_is_abs = os.path.isabs(cand) if cand else False

    if not cmd_part:
        if source_kind == "file":
            resolved_run_path = src
    elif cand_is_abs and os.path.isfile(cand):
        resolved_run_path = os.path.abspath(cand)
    elif source_kind == "dir":
        direct = os.path.join(src, cand.lstrip("\\/"))
        if os.path.isfile(direct):
            resolved_run_path = os.path.abspath(direct)
    elif source_kind == "file" and os.path.normcase(cand) == os.path.normcase(os.path.basename(src)):
        resolved_run_path = src

    target = cmd_part
    if resolved_run_path:
        if source_kind == "file":
            if resolved_run_path == src or _relpath_if_within(resolved_run_path, src):
                target = os.path.basename(src)
            elif not cand_is_abs:
                target = resolved_run_path
        elif source_kind == "dir":
            rel = _relpath_if_within(resolved_run_path, src)
            if rel and rel != ".":
                target = rel
            elif not cand_is_abs:
                target = resolved_run_path
        elif not cand_is_abs:
            target = resolved_run_path

    return resolved_run_path, target.replace("/", "\\")


def _looks_like_self_elevating_script(path: str) -> bool:
    """Recognize common script self-elevation patterns so Hidden Run can elevate cleanly."""
    try:
        if not path or not os.path.isfile(path) or os.path.splitext(path)[1].lower() not in (".bat", ".cmd", ".ps1"):
            return False
        with open(path, "rb") as f:
            content = f.read(65536).decode("utf-8-sig", errors="replace")
        active = "\n".join(
            line for line in content.splitlines()
            if not _COMMENT_LINE_RE.match(line)
        )
        return bool(
            _SELF_ELEVATE_RE.search(active)
            or (_ADMIN_PROBE_RE.search(active) and _RUNAS_RE.search(active))
        )
    except (OSError, UnicodeError):
        return False


# --- IN-MEMORY ICON UTILITIES ---
def _to_square_rgba(img: Image.Image) -> Image.Image:
    src = img if img.mode == "RGBA" else img.convert("RGBA")
    if src.width != src.height:
        side = max(src.width, src.height)
        square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
        square.paste(src, ((side - src.width) // 2, (side - src.height) // 2))
        return square
    return src


def build_multi_ico_bytes(
    master_img: Image.Image, sizes: tuple[tuple[int, int], ...] | None = None
) -> bytes:
    """Convert a PIL image into multi-resolution Windows .ico bytes in memory."""
    try:
        src = (
            master_img
            if (master_img.mode == "RGBA" and master_img.width == master_img.height)
            else _to_square_rgba(master_img)
        )
        buf = io.BytesIO()
        src.save(
            buf,
            format="ICO",
            sizes=list(sizes) if sizes is not None else [
                (256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)
            ],
        )
        return buf.getvalue()
    except Exception:
        return b""



def _optimize_ico_png_chunks(ico_data: bytes) -> bytes:
    """Optimize PNG-compressed ICO entries without removing existing icon sizes.

    Large (64px+) uncompressed DIB/BMP frames can also be converted to PNG if
    their decoded RGBA pixels remain identical. Windows Vista+ understands PNG
    frames in ICO. Smaller BMP icons stay untouched for compatibility.
    """
    if len(ico_data) < 6:
        return ico_data
    reserved, icon_type, count = struct.unpack_from("<HHH", ico_data)
    if reserved != 0 or icon_type != 1 or not 0 < count <= 256:
        return ico_data
    directory_end = 6 + 16 * count
    if len(ico_data) < directory_end:
        return ico_data

    entries: list[tuple[bytes, bytes]] = []
    for idx in range(count):
        header = bytes(ico_data[6 + 16 * idx:6 + 16 * (idx + 1)])
        width = header[0] or 256
        height = header[1] or 256
        chunk_size, offset = struct.unpack_from("<II", header, 8)
        if (not chunk_size or offset < directory_end or
                offset > len(ico_data) or chunk_size > len(ico_data) - offset):
            return ico_data
        chunk = ico_data[offset:offset + chunk_size]
        is_png = chunk.startswith(b"\x89PNG\r\n\x1a\n")
        # A single-frame ICO permits Pillow to interpret BMP's AND alpha mask.
        if is_png or (width >= 64 and height >= 64):
            try:
                single_header = (struct.pack("<HHH", 0, 1, 1) +
                                 header[:8] + struct.pack("<II", len(chunk), 22))
                with Image.open(io.BytesIO(single_header + chunk)) as decoded:
                    pixels = decoded.convert("RGBA")
                out = io.BytesIO()
                pixels.save(out, format="PNG", optimize=True, compress_level=9)
                candidate = out.getvalue()
                if len(candidate) < len(chunk):
                    with Image.open(io.BytesIO(candidate)) as checked:
                        if (checked.size == pixels.size and
                                checked.convert("RGBA").tobytes() == pixels.tobytes()):
                            chunk = candidate
            except (OSError, ValueError, struct.error):
                pass
        entries.append((header, chunk))

    new_data = bytearray(struct.pack("<HHH", 0, 1, count))
    data_offset = directory_end
    for header, chunk in entries:
        new_data.extend(header[:8])
        new_data.extend(struct.pack("<II", len(chunk), data_offset))
        data_offset += len(chunk)
    for _, chunk in entries:
        new_data.extend(chunk)
    result = bytes(new_data)
    return result if len(result) < len(ico_data) else ico_data


def _render_parcel_canvas(canvas: int = 512, stroke_scale: float = 1.08) -> Image.Image:
    factor = canvas / 214.0
    img = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    ink = "#383838"

    def xy(x, y):
        return (round(x * factor), round(y * factor))

    outer = [(12, 53), (105, 15), (198, 53), (198, 162), (106, 205), (12, 162)]
    draw.polygon([xy(*p) for p in outer], fill="#ffffff")

    strokes = (
        (outer + [(12, 53)], 6.8),
        ([(12, 53), (106, 96), (198, 53)], 6.8),
        ([(106, 96), (106, 205)], 6.8),
        ([(43, 40), (138, 80)], 6.0),
        ([(76, 27), (166, 68)], 6.0),
        ([(139, 80), (139, 120), (166, 110), (166, 68)], 6.2),
    )
    for points, width in strokes:
        w = max(1, round(width * stroke_scale * factor))
        coords = [xy(*p) for p in points]
        draw.line(coords, fill=ink, width=w, joint="curve")
        r = w / 2.0
        for cx, cy in (coords[0], coords[-1]):
            draw.ellipse((round(cx - r), round(cy - r), round(cx + r), round(cy + r)), fill=ink)
    return img


_DEFAULT_PARCEL_IMAGE: Image.Image | None = None
_DEFAULT_SFX_ICON_BYTES: bytes = b""
_DEFAULT_SFX_COMPACT_ICON_BYTES: bytes = b""


def get_default_parcel_image() -> Image.Image:
    global _DEFAULT_PARCEL_IMAGE
    if _DEFAULT_PARCEL_IMAGE is None:
        _DEFAULT_PARCEL_IMAGE = _render_parcel_canvas()
    return _DEFAULT_PARCEL_IMAGE


def get_default_sfx_icon_bytes(compact: bool = False) -> bytes:
    global _DEFAULT_SFX_ICON_BYTES, _DEFAULT_SFX_COMPACT_ICON_BYTES
    if not _DEFAULT_SFX_ICON_BYTES:
        _DEFAULT_SFX_ICON_BYTES = build_multi_ico_bytes(get_default_parcel_image())
    if not compact:
        return _DEFAULT_SFX_ICON_BYTES
    if not _DEFAULT_SFX_COMPACT_ICON_BYTES:
        candidate = build_multi_ico_bytes(
            get_default_parcel_image(), ((256, 256), (48, 48), (32, 32), (16, 16))
        )
        compact_data = candidate if candidate and len(candidate) < len(_DEFAULT_SFX_ICON_BYTES) else _DEFAULT_SFX_ICON_BYTES
        _DEFAULT_SFX_COMPACT_ICON_BYTES = _optimize_ico_png_chunks(compact_data)
    return _DEFAULT_SFX_COMPACT_ICON_BYTES


def load_pil_from_ico_bytes(data: bytes) -> Image.Image | None:
    """Load the highest-resolution, highest-bit-depth RGBA image from raw .ico bytes."""
    if not data:
        return None
    try:
        with Image.open(io.BytesIO(data)) as source:
            ico_reader = getattr(source, "ico", None)
            entries = getattr(ico_reader, "entry", None)
            if ico_reader is not None and entries:
                def _entry_key(idx: int) -> tuple[int, int, int]:
                    e = entries[idx]
                    if isinstance(e, dict):
                        w, h = e.get("dim") or (e.get("width", 0), e.get("height", 0))
                        bpp = e.get("bpp") or e.get("color_depth") or 32
                        sz = e.get("size", 0)
                    else:
                        w, h = getattr(e, "dim", (getattr(e, "width", 0), getattr(e, "height", 0)))
                        bpp = getattr(e, "bpp", 0) or 32
                        sz = getattr(e, "size", 0)
                    return ((w or 256) * (h or 256), bpp, sz)

                for idx in sorted(range(len(entries)), key=_entry_key, reverse=True):
                    try:
                        frame = ico_reader.frame(idx)
                        frame.load()
                        return _to_square_rgba(frame)
                    except Exception:
                        continue

            source.load()
            rgba = _to_square_rgba(source)
            return rgba.copy() if rgba is source else rgba
    except Exception:
        return None


def pil_to_qpixmap(pil_img: Image.Image, logical_size: int, dpr: float = 1.0) -> QPixmap:
    target_px = max(1, round(logical_size * dpr))
    img = (
        pil_img
        if (pil_img.mode == "RGBA" and pil_img.width == pil_img.height)
        else _to_square_rgba(pil_img)
    )
    if img.size != (target_px, target_px):
        img = img.resize((target_px, target_px), Image.Resampling.LANCZOS)
    raw_bgra = img.tobytes("raw", "BGRA")
    qimg = QImage(raw_bgra, target_px, target_px, target_px * 4, QImage.Format.Format_ARGB32)
    pixmap = QPixmap.fromImage(qimg)
    pixmap.setDevicePixelRatio(dpr)
    return pixmap


def _extract_pe_icon_bytes(pe_path: str, icon_index: int = 0) -> bytes:
    """Extract raw RT_GROUP_ICON + RT_ICON bytes directly from a PE (.exe/.dll/.mun) file."""
    if not pe_path:
        return b""

    hmod = _KERNEL32.LoadLibraryExW(pe_path, None, 0x00000022)
    if not hmod:
        return b""

    try:
        def _read_res(res_type: int, res_id) -> bytes:
            if isinstance(res_id, int):
                if not (0 < res_id < 0x10000):
                    return b""
                name_ptr = ctypes.c_void_p(res_id)
            else:
                if not res_id:
                    return b""
                name_ptr = ctypes.cast(ctypes.c_wchar_p(str(res_id)), ctypes.c_void_p)
            hres = _KERNEL32.FindResourceW(hmod, name_ptr, ctypes.c_void_p(res_type))
            if not hres:
                return b""
            size = _KERNEL32.SizeofResource(hmod, hres)
            hglob = _KERNEL32.LoadResource(hmod, hres) if size else None
            ptr = _KERNEL32.LockResource(hglob) if hglob else None
            return ctypes.string_at(ptr, size) if ptr else b""

        grp_data = b""
        if icon_index < 0:
            abs_id = abs(icon_index)
            grp_data = _read_res(14, abs_id) or _read_res(14, str(abs_id))
            if not grp_data:
                return b""
        else:
            target_res_id = None
            current_idx = 0

            def _enum_cb(_hModule, _lpszType, lpszName, _lParam):
                nonlocal current_idx, target_res_id
                if not lpszName:
                    return 0
                if current_idx == icon_index:
                    target_res_id = int(lpszName) if lpszName < 0x10000 else ctypes.wstring_at(lpszName)
                    return 0
                current_idx += 1
                return 1

            cb_func = _ENUMRESNAMEPROCW(_enum_cb)
            _KERNEL32.EnumResourceNamesW(hmod, ctypes.c_void_p(14), cb_func, 0)
            if target_res_id is None:
                return b""

            grp_data = _read_res(14, target_res_id)

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
            n_id, = struct.unpack_from("<H", grp_data, pos + 12)
            chunk = _read_res(3, n_id)
            if chunk:
                hdr_8 = bytearray(grp_data[pos:pos + 8])
                hdr_8[3] = 0  # Ensure bReserved is 0 for strict ICO readers
                valid_layers.append((bytes(hdr_8) + struct.pack("<I", len(chunk)), chunk))

        if not valid_layers:
            return b""

        def _layer_sort_key(item: tuple[bytes, bytes]) -> tuple[int, int, int]:
            fixed_12, chunk = item
            w = fixed_12[0] or 256
            h = fixed_12[1] or 256
            bpp, = struct.unpack_from("<H", fixed_12, 6)
            return (w * h, bpp or 32, len(chunk))

        valid_layers.sort(key=_layer_sort_key, reverse=True)

        offset = 6 + 16 * len(valid_layers)
        out = bytearray(struct.pack("<HHH", 0, 1, len(valid_layers)))
        for fixed_12, chunk in valid_layers:
            out.extend(fixed_12)
            out.extend(struct.pack("<I", offset))
            offset += len(chunk)
        for _, chunk in valid_layers:
            out.extend(chunk)

        return bytes(out)
    finally:
        _KERNEL32.FreeLibrary(hmod)


def _split_icon_source(file_path: str, icon_idx: int | None = None) -> tuple[str, int | None]:
    if not file_path:
        return "", None
    cleaned = expand_path(file_path)
    if os.path.isfile(cleaned):
        ext = os.path.splitext(cleaned)[1].lower()
        return cleaned, (None if ext in _DIRECT_ICON_EXTS else icon_idx)
    if icon_idx is None and "," in file_path:
        path_part, idx_part = file_path.rsplit(",", 1)
        cand_path = expand_path(path_part)
        try:
            cand_idx = int(idx_part.strip())
        except ValueError:
            return "", None
        if os.path.isfile(cand_path):
            ext = os.path.splitext(cand_path)[1].lower()
            return cand_path, (None if ext in _DIRECT_ICON_EXTS else cand_idx)
    return "", None


def extract_icon_from_file(resolved_path: str, icon_idx: int | None = None) -> tuple[bytes, Image.Image | None]:
    """Extract or convert .ico bytes from a validated path and return (ico_bytes, optional_cached_pil_img)."""
    if not resolved_path:
        return b"", None

    ext = os.path.splitext(resolved_path)[1].lower()
    if ext == ".ico":
        try:
            with open(resolved_path, "rb") as f:
                raw = f.read()
            pil_img = load_pil_from_ico_bytes(raw)
            return (raw, pil_img) if pil_img is not None else (b"", None)
        except OSError:
            return b"", None

    if ext in (".png", ".jpg", ".jpeg", ".jxl"):
        try:
            with Image.open(resolved_path) as img:
                img.load()
                rgba = _to_square_rgba(img)
                if rgba is img:
                    rgba = img.copy()
            ico_bytes = build_multi_ico_bytes(rgba)
            return (ico_bytes, rgba) if ico_bytes else (b"", None)
        except Exception:
            return b"", None

    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    sys32 = os.path.join(sys_root, "System32")
    if icon_idx is None:
        known_map = {
            ".ps1": (os.path.join(sys32, r"WindowsPowerShell\v1.0\powershell.exe"), 0),
            ".reg": (os.path.join(sys_root, "regedit.exe"), 0),
            ".msi": (os.path.join(sys32, "msiexec.exe"), 0),
            ".bat": (os.path.join(sys32, "imageres.dll"), -68),
            ".cmd": (os.path.join(sys32, "imageres.dll"), -68),
            ".vbs": (os.path.join(sys32, "wscript.exe"), 0),
            ".js": (os.path.join(sys32, "wscript.exe"), 0),
            ".wsf": (os.path.join(sys32, "wscript.exe"), 0),
            ".msc": (os.path.join(sys32, "mmc.exe"), 0),
        }
        target_bin, icon_idx = known_map.get(ext, (resolved_path, 0))
    else:
        target_bin = resolved_path

    mun_path = os.path.join(sys_root, "SystemResources", os.path.basename(target_bin) + ".mun")
    candidates = (mun_path, target_bin) if os.path.isfile(mun_path) else (target_bin,)
    indices = (icon_idx, 0) if icon_idx < 0 else (icon_idx,)

    for idx in indices:
        for candidate in candidates:
            ico_bytes = _extract_pe_icon_bytes(candidate, idx)
            if ico_bytes:
                pil_img = load_pil_from_ico_bytes(ico_bytes)
                if pil_img is not None:
                    return ico_bytes, pil_img

    return b"", None


def _get_app_dir() -> str:
    """Find companion 7-Zip tools next to the script or frozen application."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _find_executable(
    candidates: tuple[str, ...], cmd_name: str, search_path: bool = True
) -> str:
    cached = _CACHED_TOOL_PATHS.get(cmd_name)
    if cached and os.path.isfile(cached):
        return cached
    for cand in candidates:
        if os.path.isfile(cand):
            _CACHED_TOOL_PATHS[cmd_name] = cand
            return cand
    if search_path:
        found = shutil.which(cmd_name)
        if found and os.path.isfile(found):
            _CACHED_TOOL_PATHS[cmd_name] = found
            return found
    return ""


# ==============================================================================
# 2. CORE ENGINE: BACKGROUND SFX BUILDER & C# STUB COMPILER
# ==============================================================================
class SFXBuilderWorker(QThread):
    progress = pyqtSignal(int)
    build_finished = pyqtSignal(bool, str)

    DICT_SCAN_CAP_BYTES = 65 * 1024 * 1024  # >64 MB selects -md=128m

    def __init__(self, config: dict):
        super().__init__()
        self.cfg = config
        self._cancelled = False
        self._proc_lock = threading.Lock()
        self._active_proc: subprocess.Popen | None = None
        self.output_exe_path: str = ""

        pw = config["password"]
        if pw:
            self._expected_user_pw_hash = hashlib.sha256(pw.encode("utf-8")).hexdigest()
            self._archive_7z_pw = pw
            self._stub_embedded_7z_pw = ""
        elif config["crypto"]:
            self._expected_user_pw_hash = ""
            self._archive_7z_pw = uuid.uuid4().hex
            self._stub_embedded_7z_pw = self._archive_7z_pw
        else:
            self._expected_user_pw_hash = ""
            self._archive_7z_pw = ""
            self._stub_embedded_7z_pw = ""

    def cancel(self):
        with self._proc_lock:
            self._cancelled = True
            proc = self._active_proc
        if proc is not None and proc.poll() is None and proc.pid:
            threading.Thread(
                target=lambda: subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=5,
                ),
                daemon=True,
            ).start()

    def _start_process(self, cmd, **kwargs):
        """Make cancellation and subprocess registration one synchronized operation."""
        with self._proc_lock:
            if self._cancelled:
                return None
            proc = subprocess.Popen(cmd, **kwargs)
            self._active_proc = proc
            return proc

    @staticmethod
    def find_7zip() -> str:
        """Locate an archive writer; prefer full 7z, then standalone 7za/7zr.

        Companion executables are resolved relative to the real application
        folder, including the PyInstaller one-file case.
        """
        app_dir = _get_app_dir()
        full_7z = _find_executable(
            (
                r"C:\Program Files\7-Zip\7z.exe",
                r"C:\Program Files (x86)\7-Zip\7z.exe",
                os.path.join(app_dir, "7z.exe"),
            ),
            "7z",
        )
        if full_7z:
            return full_7z

        seven_za = _find_executable((
            r"C:\Program Files\7-Zip\x64\7za.exe",
            os.path.join(app_dir, "7za.exe"),
            r"C:\Program Files\7-Zip\7za.exe",
            r"C:\Program Files (x86)\7-Zip\7za.exe",
        ), "7za", search_path=False)
        if seven_za:
            return seven_za
        seven_zr = _find_executable((
            r"C:\Program Files\7-Zip\7zr.exe",
            os.path.join(app_dir, "7zr.exe"),
            r"C:\Program Files (x86)\7-Zip\7zr.exe",
        ), "7zr", search_path=False)
        if seven_zr:
            return seven_zr
        return _find_executable((), "7za") or _find_executable((), "7zr")

    @staticmethod
    def find_csc() -> str:
        win_dir = os.environ.get("SystemRoot", r"C:\Windows")
        return _find_executable(
            (
                os.path.join(win_dir, r"Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
                os.path.join(win_dir, r"Microsoft.NET\Framework\v4.0.30319\csc.exe"),
            ),
            "csc",
        )

    def _get_source_total_size(self, source_path: str, is_dir: bool) -> int:
        """Scan source size up to DICT_SCAN_CAP_BYTES (65 MB) in a single scandir pass."""
        if not is_dir:
            try:
                return os.path.getsize(source_path)
            except OSError:
                return 0
        total = 0
        stack = [source_path]
        while stack and not self._cancelled:
            current_dir = stack.pop()
            try:
                with os.scandir(current_dir) as entries:
                    for entry in entries:
                        if self._cancelled:
                            return total
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                total += entry.stat(follow_symlinks=False).st_size
                                if total >= self.DICT_SCAN_CAP_BYTES:
                                    return total
                        except OSError:
                            pass
            except OSError:
                pass
        return total

    @staticmethod
    def _select_7z_dict_flag(total_bytes: int) -> str:
        """Choose an LZMA2 dictionary size proportional to the input size for fast startup and compression."""
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

    def _iter_output_candidates(self, base_name: str):
        out_dir = self.cfg["output"]
        yield os.path.join(out_dir, f"{base_name}.exe")
        fs_stamp = datetime.now().strftime("%d.%m.%Y %H.%M.%S")
        yield os.path.join(out_dir, f"{base_name}_{fs_stamp}.exe")
        counter = 2
        while True:
            yield os.path.join(out_dir, f"{base_name}_{fs_stamp} ({counter}).exe")
            counter += 1

    def _commit_staging_exe(self, staging_exe: str, base_name: str) -> str:
        """Move staging file to final path; when Don't Replace is active, use non-overwriting os.rename."""
        out_dir = self.cfg["output"]
        if not self.cfg["dont_replace"]:
            target_exe = os.path.join(out_dir, f"{base_name}.exe")
            os.replace(staging_exe, target_exe)
            return target_exe
        for cand in self._iter_output_candidates(base_name):
            try:
                os.rename(staging_exe, cand)
                return cand
            except FileExistsError:
                continue
        raise RuntimeError("Failed to commit output executable.")

    def build_7z_archive(self, seven_zip: str, source_path: str, archive_path: str) -> int:
        is_dir = self.cfg["source_kind"] == "dir"
        cmd = [seven_zip, "a", "-bso0", "-bsp1"]
        source_bytes = 0
        if self.cfg["compress"]:
            source_bytes = self._get_source_total_size(source_path, is_dir)
            dict_flag = self._select_7z_dict_flag(source_bytes)
            cmd.extend([
                "-t7z", "-mx=9", "-m0=lzma2", dict_flag,
                "-mfb=273", "-ms=on", "-mqs=on", "-mmt=on",
            ])
        else:
            cmd.extend(["-t7z", "-mx=0", "-mmt=on"])

        if self._archive_7z_pw:
            cmd.extend([f"-p{self._archive_7z_pw}", "-mhe=on"])
        cmd.extend(["-y", archive_path, "--"])
        cmd.append(os.path.join(source_path, "*") if is_dir else source_path)

        proc = self._start_process(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc is None:
            return 255
        last_mapped = 20
        try:
            with proc:
                if proc.stdout is not None:
                    fd = proc.stdout.fileno()
                    while True:
                        raw_chunk = os.read(fd, 1024)
                        if not raw_chunk:
                            break
                        matches = _PCT_RE.findall(raw_chunk)
                        if matches:
                            pct = min(100, int(matches[-1]))
                            mapped = 20 + (pct * 40) // 100
                            if mapped > last_mapped:
                                last_mapped = mapped
                                self.progress.emit(mapped)
                ret_code = proc.wait()
        finally:
            with self._proc_lock:
                self._active_proc = None

        # One 7z pass for small/medium payloads instead of 1 baseline plus
        # 2 slower speculative recompressions. Extractor compatibility is
        # verified only when the final runtime is selected for compilation.
        return ret_code

    def _test_extractor_archive(self, extractor: str, archive_path: str) -> bool:
        """Test the exact 7z stream, including password, with an extractor."""
        if not archive_path:
            return True
        cmd = [extractor, "t", "-t7z", "-y", "-bso0", "-bsp0"]
        if self._archive_7z_pw:
            cmd.append(f"-p{self._archive_7z_pw}")
        cmd.extend(["--", archive_path])
        try:
            proc = self._start_process(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if proc is None:
                return False
            try:
                with proc:
                    return proc.wait() == 0
            finally:
                with self._proc_lock:
                    self._active_proc = None
        except OSError:
            return False

    def _extractor_supports_aes(self, extractor: str) -> bool:
        """Inspect 7zr capabilities once per unchanged executable."""
        try:
            st = os.stat(extractor)
            key = (os.path.normcase(os.path.abspath(extractor)), st.st_mtime_ns, st.st_size)
            if key in _CACHED_AES_SUPPORT:
                return _CACHED_AES_SUPPORT[key]
            proc = self._start_process(
                [extractor, "i"], stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if proc is None:
                return False
            try:
                with proc:
                    output, _ = proc.communicate()
                    supported = (proc.returncode == 0 and
                                 bool(re.search(rb"7z\s*aes|7zaes|aes256", output, re.I)))
                    if len(_CACHED_AES_SUPPORT) >= 8:
                        _CACHED_AES_SUPPORT.pop(next(iter(_CACHED_AES_SUPPORT)))
                    _CACHED_AES_SUPPORT[key] = supported
                    return supported
            finally:
                with self._proc_lock:
                    self._active_proc = None
        except OSError:
            return False

    @staticmethod
    def _prepare_runtime_resource(
        source_path: str, work_dir: str, resource_name: str, compress: bool
    ) -> tuple[str, str]:
        """Embed the smallest tested encoding; leave uncompressed mode unchanged."""
        if not compress:
            return source_path, resource_name

        mode, payload = _get_optimal_runtime_pack(source_path)
        if mode == "raw":
            return source_path, resource_name
        packed_name = resource_name + {"bcj": ".bcj", "def": ".def", "gz": ".gz"}[mode]
        packed_path = os.path.join(work_dir, packed_name)
        with open(packed_path, "wb") as output:
            output.write(payload)
        return packed_path, packed_name

    @staticmethod
    def _embedded_runtime_size(path: str) -> int:
        """Use the exact packing logic that the final compiler resources use."""
        return len(_get_optimal_runtime_pack(path)[1])

    def _select_sfx_extractor(
        self, installed_7z: str, archive_path: str = ""
    ) -> tuple[str, str]:
        """Choose smallest supported 7z runtime, confirming format and AES.

        7zr can only be used for encrypted archives if its own method list
        confirms AES and it can test the EXACT archive. Installed 7z remains
        the safe fallback. Path precedence remains identical to v2.
        """
        dll_path = os.path.join(os.path.dirname(installed_7z), "7z.dll")
        # 7za/7zr are standalone: do not accidentally bundle an adjacent
        # 7z.dll when a standalone binary was used to create the archive.
        needs_dll = os.path.basename(installed_7z.replace("\\", "/")).lower() == "7z.exe"
        installed = (installed_7z, dll_path if needs_dll and os.path.isfile(dll_path) else "")
        if not self.cfg["compress"]:
            return installed
        exe_dir = os.path.dirname(installed_7z)
        app_dir = _get_app_dir()
        names = ("7zr.exe", "7za.exe", "7zz.exe")
        preferred_paths = {
            "7zr.exe": (
                r"C:\Program Files\7-Zip\7zr.exe",
                os.path.join(app_dir, "7zr.exe"),
            ),
            "7za.exe": (
                r"C:\Program Files\7-Zip\x64\7za.exe",
                os.path.join(app_dir, "7za.exe"),
                r"C:\Program Files\7-Zip\7za.exe",
            ),
            "7zz.exe": (
                os.path.join(exe_dir, "7zz.exe"),
                os.path.join(app_dir, "7zz.exe"),
            ),
        }
        candidates = []
        visited = set()
        for name in names:
            search_order = list(preferred_paths[name])
            fallback = shutil.which(name)
            if fallback:
                search_order.append(fallback)
            for candidate in search_order:
                key = os.path.normcase(os.path.abspath(candidate))
                if key not in visited and os.path.isfile(candidate):
                    candidates.append((candidate, ""))
                    visited.add(key)
                    break
        candidates.append(installed)

        sizes = []
        for executable, dependency in candidates:
            if (self._archive_7z_pw and
                    os.path.basename(executable.replace("\\", "/")).lower() == "7zr.exe" and
                    not self._extractor_supports_aes(executable)):
                continue
            try:
                size = self._embedded_runtime_size(executable)
                if dependency:
                    size += self._embedded_runtime_size(dependency)
                sizes.append((size, executable, dependency))
            except OSError:
                pass
        sizes.sort(key=lambda item: item[0])
        for _, executable, dependency in sizes:
            if self._test_extractor_archive(executable, archive_path):
                return executable, dependency
        if archive_path:
            raise RuntimeError(
                "No available 7-Zip runtime could verify the generated archive. "
                "The package was not created to avoid producing an unreadable EXE."
            )
        return installed

    def _compile_uninstaller_resource(self, csc_path: str, work_dir: str,
                                      app_name: str, icon_file: str) -> tuple[str, str]:
        """Compile an embedded, manifest-driven silent uninstaller only for installer packages."""
        uninstall_source = r'''using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Reflection;
using Microsoft.Win32;

[assembly: AssemblyTitle("__APP_NAME__ Uninstaller")]
[assembly: AssemblyProduct("__APP_NAME__")]
namespace ByteWrapperUninstaller
{
    static class Program
    {
        private const string PackageId = "__PACKAGE_ID__";
        private const string Header = "BW_UNINSTALL_V1|" + PackageId;
        private const string ManifestName = "Uninstall.info";
        private const string UninstallerName = "Uninstall.exe";

        [STAThread]
        static void Main(string[] args)
        {
            try
            {
                if (args.Length == 3 && args[0] == "--bw-uninstall")
                {
                    // Wait until the original Uninstall.exe releases its file handle.
                    int parentPid;
                    if (int.TryParse(args[2], out parentPid))
                    {
                        try { using (Process parent = Process.GetProcessById(parentPid))
                            parent.WaitForExit(5000); }
                        catch { }
                    }
                    RemoveInstalledFiles(args[1]);
                    QueueTemporaryExeCleanup();
                    return;
                }
                string installDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                if (string.IsNullOrEmpty(installDir) || !File.Exists(Path.Combine(installDir, ManifestName)))
                    return;
                string tempCopy = Path.Combine(Path.GetTempPath(),
                    "bw_uninstaller_" + Guid.NewGuid().ToString("N") + ".exe");
                File.Copy(Assembly.GetExecutingAssembly().Location, tempCopy, false);
                ProcessStartInfo psi = new ProcessStartInfo(tempCopy,
                    "--bw-uninstall " + Quote(installDir) + " " + Process.GetCurrentProcess().Id);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }
            catch { /* An unattended uninstaller must not display a dialog. */ }
        }

        private static string UninstallRegistryKey(string installDir)
        {
            string canonical = Path.GetFullPath(installDir).TrimEnd('\\').ToUpperInvariant();
            using (SHA256 hash = SHA256.Create())
            {
                byte[] bytes = hash.ComputeHash(Encoding.UTF8.GetBytes(canonical));
                string suffix = BitConverter.ToString(bytes).Replace("-", "").Substring(0, 16);
                return @"Software\Microsoft\Windows\CurrentVersion\Uninstall\ByteWrapper_" + PackageId + "_" + suffix;
            }
        }

        private static string Quote(string path)
        {
            // A trailing backslash must be doubled before a Windows closing quote.
            if (path.EndsWith("\\")) path += "\\";
            return "\"" + path.Replace("\"", "\\\"") + "\"";
        }

        private static string Decode(string base64)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        }

        private static string FileDigest(string path)
        {
            using (FileStream input = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "");
        }

        private static bool IsWithin(string root, string candidate)
        {
            string prefix = Path.GetFullPath(root).TrimEnd('\\') + "\\";
            return candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        private static bool RemoveVerifiedFile(string path, string expectedHash)
        {
            try
            {
                if (!File.Exists(path)) return true;
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) return false;
                if (!string.Equals(FileDigest(path), expectedHash, StringComparison.OrdinalIgnoreCase))
                    return false; // Never remove files modified after installation.
                FileAttributes flags = File.GetAttributes(path);
                if ((flags & FileAttributes.ReadOnly) != 0)
                    File.SetAttributes(path, flags & ~FileAttributes.ReadOnly);
                File.Delete(path);
                return true;
            }
            catch { return false; }
        }

        private static void RemoveInstalledFiles(string installationPath)
        {
            string root = Path.GetFullPath(installationPath);
            string info = Path.Combine(root, ManifestName);
            if (!File.Exists(info)) return;
            string[] lines = File.ReadAllLines(info, Encoding.UTF8);
            if (lines.Length < 2 || lines[0] != Header || !lines[1].StartsWith("ROOT|")) return;
            if (!string.Equals(Path.GetFullPath(Decode(lines[1].Substring(5))), root,
                    StringComparison.OrdinalIgnoreCase)) return;

            // Validate every manifest entry before doing ANY removal.
            List<string[]> files = new List<string[]>();
            List<string> folders = new List<string>();
            for (int i = 2; i < lines.Length; i++)
            {
                string[] fields = lines[i].Split('|');
                if (fields.Length == 3 && (fields[0] == "F" || fields[0] == "S"))
                {
                    string path = Decode(fields[1]);
                    if (fields[0] == "F")
                    {
                        if (Path.IsPathRooted(path)) return;
                        path = Path.GetFullPath(Path.Combine(root, path));
                        if (!IsWithin(root, path)) return;
                    }
                    else
                    {
                        if (!Path.IsPathRooted(path)) return;
                        path = Path.GetFullPath(path);
                        if (!path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) return;
                    }
                    if (fields[2].Length != 64) return;
                    files.Add(new string[] { path, fields[2] });
                }
                else if (fields.Length == 2 && fields[0] == "D")
                {
                    string path = Decode(fields[1]);
                    if (Path.IsPathRooted(path)) return;
                    path = Path.GetFullPath(Path.Combine(root, path));
                    if (!IsWithin(root, path) && !string.Equals(root, path,
                            StringComparison.OrdinalIgnoreCase)) return;
                    folders.Add(path);
                }
                else return;
            }

            bool success = true;
            foreach (string[] file in files)
                if (!RemoveVerifiedFile(file[0], file[1])) success = false;
            // If a file is locked or changed, leave the uninstall record and EXE
            // in place so the user can retry; never delete unrelated files.
            if (!success) return;
            try { File.Delete(info); }
            catch { return; }
            // Remove only this exact install entry, after verified removal succeeded.
            try { Registry.CurrentUser.DeleteSubKeyTree(UninstallRegistryKey(root), false); }
            catch { }
            try { File.Delete(Path.Combine(root, UninstallerName)); }
            catch { /* The manifest is already removed; leave a harmless EXE. */ }

            // Directories are removed ONLY if created by this installer and empty.
            folders.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
            foreach (string folder in folders)
            {
                try { if (Directory.Exists(folder)) Directory.Delete(folder, false); }
                catch { /* Existing content or other files: do not touch it. */ }
            }
        }

        private static void QueueTemporaryExeCleanup()
        {
            try
            {
                string ownPath = Assembly.GetExecutingAssembly().Location;
                if (!Path.GetFullPath(ownPath).StartsWith(Path.GetFullPath(Path.GetTempPath()),
                    StringComparison.OrdinalIgnoreCase)) return;
                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe",
                    "/C ping -n 3 127.0.0.1 >nul & del /F /Q " + Quote(ownPath));
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }
            catch { }
        }
    }
}
'''
        uninstall_source = (uninstall_source
            .replace("__APP_NAME__", app_name.replace('\\', '\\\\').replace('"', '\\"'))
            .replace("__PACKAGE_ID__", self._uninstall_package_id))
        source_file = os.path.join(work_dir, "ByteWrapperUninstaller.cs")
        output_file = os.path.join(work_dir, "ByteWrapperUninstaller.exe")
        with open(source_file, "w", encoding="utf-8-sig") as fh:
            fh.write(uninstall_source)
        cmd = [csc_path, "/nologo", "/target:winexe", "/optimize+", "/debug-",
               "/reference:System.dll", f"/win32icon:{icon_file}",
               f"/out:{output_file}", source_file]
        proc = self._start_process(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8", errors="replace",
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        if proc is None:
            raise RuntimeError("Uninstaller compilation canceled.")
        try:
            with proc:
                stdout, stderr = proc.communicate()
                code = proc.returncode
        finally:
            with self._proc_lock:
                self._active_proc = None
        if code != 0 or not os.path.isfile(output_file):
            raise RuntimeError("Uninstaller C# compilation failed:\n" + stdout + "\n" + stderr)
        return output_file, "ByteWrapperUninstaller.exe"

    def compile_csharp_sfx(
        self, csc_path: str, work_dir: str, raw_7z_path: str,
        seven_zip: str, staging_exe: str, base_name: str
    ) -> tuple[bool, str]:
        extractor_exe, seven_zip_dll = self._select_sfx_extractor(seven_zip, raw_7z_path)
        has_dll = bool(seven_zip_dll)

        exe_resource_path, exe_resource_name = self._prepare_runtime_resource(
            extractor_exe, work_dir, "7z.exe", self.cfg["compress"]
        )
        if has_dll:
            dll_resource_path, dll_resource_name = self._prepare_runtime_resource(
                seven_zip_dll, work_dir, "7z.dll", self.cfg["compress"]
            )

        source_path = self.cfg["source"]
        cmd_part = self.cfg["cmd_part"]
        run_args_raw = self.cfg["run_args"]

        if self.cfg["extract_only"]:
            resolved_run_path, run_target_rel = "", ""
        else:
            resolved_run_path, run_target_rel = _resolve_run_file(
                source_path,
                cmd_part,
                source_resolved=True,
                source_kind=self.cfg["source_kind"],
            )

        self_elevating = (
            _looks_like_self_elevating_script(resolved_run_path)
            if (self.cfg["hidden_run"] and not self.cfg["run_as_admin"]) else False
        )

        def cs_escape(s: str) -> str:
            return (
                s.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
            )

        prod_name_str = cs_escape(base_name)
        raw_desc = self.cfg["description"]
        file_desc_str = cs_escape(raw_desc if raw_desc else base_name)

        pe_ver_num, pe_ver_info = self.cfg["parsed_version"]
        pe_ver_num_str = cs_escape(pe_ver_num)
        pe_ver_info_str = cs_escape(pe_ver_info)

        extract_to_str = cs_escape(self.cfg["extract_to"])
        run_target_str = cs_escape(run_target_rel)
        run_args_str = cs_escape(run_args_raw)

        icon_bytes = self.cfg.get("icon_bytes") or get_default_sfx_icon_bytes(
            compact=self.cfg["compress"]
        )
        if self.cfg["compress"] and self.cfg.get("icon_bytes"):
            source_ext = os.path.splitext(self.cfg.get("icon_source", ""))[1].lower()
            if source_ext in (".png", ".jpg", ".jpeg", ".jxl"):
                icon_image = load_pil_from_ico_bytes(icon_bytes)
                if icon_image is not None:
                    compact_icon = build_multi_ico_bytes(
                        icon_image, ((256, 256), (48, 48), (32, 32), (16, 16))
                    )
                    if compact_icon and len(compact_icon) < len(icon_bytes):
                        icon_bytes = compact_icon
                icon_bytes = _optimize_ico_png_chunks(icon_bytes)
        work_icon_path = os.path.join(work_dir, "icon.ico")
        with open(work_icon_path, "wb") as fh:
            fh.write(icon_bytes)

        shortcut_active = bool(self.cfg.get("shortcut_active"))
        installer_mode = bool(self.cfg["extract_only"] and shortcut_active and not self.cfg["hidden_run"])
        self._uninstall_package_id = uuid.uuid4().hex if installer_mode else ""
        uninstall_resource_file = ""
        uninstall_resource_name = ""
        if installer_mode:
            uninstall_resource_file, uninstall_resource_name = self._compile_uninstaller_resource(
                csc_path, work_dir, base_name, work_icon_path
            )
        shortcut_target_rel = ""
        if shortcut_active:
            _, shortcut_target_rel = _resolve_run_file(
                source_path, self.cfg["shortcut_command"],
                source_resolved=True, source_kind=self.cfg["source_kind"]
            )
        shortcut_name_str = cs_escape(self.cfg.get("shortcut_name", "").strip())
        shortcut_path_str = cs_escape(self.cfg.get("shortcut_path", "").strip())
        shortcut_target_str = cs_escape(shortcut_target_rel)
        # .lnk files have a Description/Comment field, but no native Version
        # property. Show the explicitly entered version in that field as well.
        shortcut_comment = []
        if raw_desc.strip():
            shortcut_comment.append(raw_desc.strip())
        typed_version = self.cfg.get("version", "").strip()
        if typed_version:
            shortcut_comment.append("Version: " + typed_version)
        shortcut_description_str = cs_escape(" | ".join(shortcut_comment))
        shortcut_args_str = cs_escape(self.cfg.get("shortcut_args", ""))
        shortcut_icon_bytes = self.cfg.get("shortcut_icon_bytes") or b""
        shortcut_icon_file = ""
        shortcut_icon_resource = "ByteWrapperShortcut.ico"
        uninstall_id_str = cs_escape(self._uninstall_package_id)
        if shortcut_active:
            if not shortcut_icon_bytes and not self.cfg.get("icon_bytes") and not self.cfg["compress"]:
                shortcut_icon_file = work_icon_path
            else:
                shortcut_icon_file = os.path.join(work_dir, "shortcut_icon.ico")
                with open(shortcut_icon_file, "wb") as shortcut_ico_out:
                    shortcut_ico_out.write(shortcut_icon_bytes or get_default_sfx_icon_bytes())

        ask_user_pw = "true" if self.cfg["password"] else "false"
        expected_user_pw_hash = cs_escape(self._expected_user_pw_hash)
        internal_7z_pw_str = cs_escape(self._stub_embedded_7z_pw)

        hidden_run = "true" if self.cfg["hidden_run"] else "false"
        hidden_script_needs_admin = "true" if self_elevating else "false"
        extract_only = "true" if self.cfg["extract_only"] else "false"
        instances = "true" if self.cfg["instances"] else "false"
        self_remove = "true" if self.cfg["self_remove"] else "false"
        show_progress = "true" if self.cfg["progress_bar"] else "false"
        extract_exe_line = f'ExtractResource("{exe_resource_name}", sevenZExe);'
        extract_dll_line = (
            f'ExtractResource("{dll_resource_name}", Path.Combine(workTemp, "7z.dll"));'
            if has_dll else ""
        )

        exec_level = "requireAdministrator" if self.cfg["run_as_admin"] else "asInvoker"
        safe_xml_ver = xml_escape(pe_ver_num, {'"': '&quot;', "'": '&apos;'})
        manifest_path = os.path.join(work_dir, "app.manifest")
        manifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="{safe_xml_ver}" name="ByteWrapper.Package"/>
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

        installer_support_code = r'''        // Installer mode extracts to temporary staging first. This makes it
        // possible to identify each owned file and NEVER overwrite existing data.
        private static bool InsideFolder(string root, string path)
        {
            return Path.GetFullPath(path).StartsWith(
                Path.GetFullPath(root).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        private static void RollBackInstaller(string root, List<string> files,
            List<string> shortcuts, List<string> folders, bool withUninstaller)
        {
            foreach (string link in shortcuts)
                try { if (File.Exists(link)) File.Delete(link); } catch { }
            foreach (string file in files)
                try { if (InsideFolder(root, file) && File.Exists(file)) File.Delete(file); } catch { }
            if (withUninstaller)
            {
                try { File.Delete(Path.Combine(root, "Uninstall.info")); } catch { }
                try { File.Delete(Path.Combine(root, "Uninstall.exe")); } catch { }
            }
            folders.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
            foreach (string folder in folders)
                try { if (Directory.Exists(folder)) Directory.Delete(folder, false); } catch { }
        }

        private static void InstallPayload(string staged, string destination,
            List<string> ownedFiles, List<string> createdDirs)
        {
            Stack<string> pending = new Stack<string>();
            pending.Push(staged);
            while (pending.Count != 0)
            {
                string current = pending.Pop();
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Reparse points in installation archives are not supported.");
                foreach (string folder in Directory.GetDirectories(current))
                {
                    if ((File.GetAttributes(folder) & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Reparse points in installation archives are not supported.");
                    string relative = folder.Substring(staged.Length).TrimStart('\\');
                    string dest = Path.GetFullPath(Path.Combine(destination, relative));
                    if (!InsideFolder(destination, dest))
                        throw new IOException("Archive path escaped installation folder.");
                    if (!Directory.Exists(dest))
                    {
                        Directory.CreateDirectory(dest);
                        createdDirs.Add(dest);
                    }
                    pending.Push(folder);
                }
                foreach (string file in Directory.GetFiles(current))
                {
                    if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                        throw new IOException("Reparse points in installation archives are not supported.");
                    string relative = file.Substring(staged.Length).TrimStart('\\');
                    string dest = Path.GetFullPath(Path.Combine(destination, relative));
                    if (!InsideFolder(destination, dest))
                        throw new IOException("Archive path escaped installation folder.");
                    if (File.Exists(dest)) continue;
                    File.Copy(file, dest, false);
                    ownedFiles.Add(dest);
                }
            }
        }

        private static string ToB64(string input)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
        }

        private static string Sha256(string file)
        {
            using (FileStream stream = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
        }

        private static void WriteUninstallInfo(string info, string root,
            List<string> owned, List<string> shortcuts, List<string> folders)
        {
            using (StreamWriter writer = new StreamWriter(
                new FileStream(info, FileMode.CreateNew, FileAccess.Write), new UTF8Encoding(false)))
            {
                writer.WriteLine("BW_UNINSTALL_V1|" + UNINSTALL_PACKAGE_ID);
                writer.WriteLine("ROOT|" + ToB64(Path.GetFullPath(root)));
                foreach (string file in owned)
                {
                    if (!InsideFolder(root, file)) continue;
                    if (!File.Exists(file)) continue;
                    string relative = file.Substring(Path.GetFullPath(root).TrimEnd('\\').Length).TrimStart('\\');
                    writer.WriteLine("F|" + ToB64(relative) + "|" + Sha256(file));
                }
                foreach (string shortcut in shortcuts)
                    if (File.Exists(shortcut))
                        writer.WriteLine("S|" + ToB64(Path.GetFullPath(shortcut)) + "|" + Sha256(shortcut));
                foreach (string folder in folders)
                {
                    string relative = string.Equals(Path.GetFullPath(folder), Path.GetFullPath(root),
                        StringComparison.OrdinalIgnoreCase) ? "." :
                        folder.Substring(Path.GetFullPath(root).TrimEnd('\\').Length).TrimStart('\\');
                    writer.WriteLine("D|" + ToB64(relative));
                }
            }
        }

''' if installer_mode else ""
        if installer_mode:
            installer_support_code += '        private static string UninstallRegistryKey(string installDir)\n        {\n            string canonical = Path.GetFullPath(installDir).TrimEnd(\'\\\\\').ToUpperInvariant();\n            using (SHA256 hash = SHA256.Create())\n            {\n                byte[] bytes = hash.ComputeHash(Encoding.UTF8.GetBytes(canonical));\n                string suffix = BitConverter.ToString(bytes).Replace("-", "").Substring(0, 16);\n                return @"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ByteWrapper_" + UNINSTALL_PACKAGE_ID + "_" + suffix;\n            }\n        }\n\n        private static void RegisterWindowsUninstall(string installDir)\n        {\n            string keyName = UninstallRegistryKey(installDir);\n            try\n            {\n                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(keyName))\n                {\n                    if (key == null) throw new IOException("Could not register the uninstaller.");\n                    string uninstallExe = Path.Combine(installDir, "Uninstall.exe");\n                    key.SetValue("DisplayName", "{prod_name_str}", RegistryValueKind.String);\n                    key.SetValue("DisplayVersion", "{pe_ver_info_str}", RegistryValueKind.String);\n                    key.SetValue("Publisher", "Byte Wrapper", RegistryValueKind.String);\n                    key.SetValue("InstallLocation", installDir, RegistryValueKind.String);\n                    key.SetValue("DisplayIcon", uninstallExe + ",0", RegistryValueKind.String);\n                    key.SetValue("UninstallString", "\\"" + uninstallExe + "\\"", RegistryValueKind.String);\n                    key.SetValue("QuietUninstallString", "\\"" + uninstallExe + "\\"", RegistryValueKind.String);\n                    key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"), RegistryValueKind.String);\n                    key.SetValue("NoModify", 1, RegistryValueKind.DWord);\n                    key.SetValue("NoRepair", 1, RegistryValueKind.DWord);\n                }\n            }\n            catch\n            {\n                try { Registry.CurrentUser.DeleteSubKeyTree(keyName, false); } catch { }\n                throw;\n            }\n        }\n'.replace("{prod_name_str}", prod_name_str).replace("{pe_ver_info_str}", pe_ver_info_str)
        installer_ui_code = r'''        // Only visible installer packages contain this UI and the uninstaller resource.
        // The monochrome controls directly override the build-time shortcut settings.
        private sealed class GrayToggle : CheckBox
        {
            private static readonly Font LabelFont = new Font("Segoe UI", 8F);

            public GrayToggle(string title)
            {
                Text = title;
                Checked = true;
                AutoSize = false;
                Height = 24;
                Width = 145;
                SetStyle(ControlStyles.AllPaintingInWmPaint |
                    ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer, true);
            }
            protected override void OnPaint(PaintEventArgs e)
            {
                e.Graphics.Clear(Parent != null ? Parent.BackColor : Color.FromArgb(249, 249, 249));
                e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
                Rectangle r = new Rectangle(2, 6, 28, 14);
                using (GraphicsPath p = new GraphicsPath())
                {
                    p.AddArc(r.Left, r.Top, 14, 14, 90, 180);
                    p.AddArc(r.Right - 14, r.Top, 14, 14, 270, 180);
                    p.CloseFigure();
                    using (SolidBrush b = new SolidBrush(Checked
                        ? Color.FromArgb(104, 104, 104) : Color.FromArgb(191, 191, 191)))
                        e.Graphics.FillPath(b, p);
                }
                int cx = Checked ? 22 : 9;
                using (SolidBrush b = new SolidBrush(Color.WhiteSmoke))
                    e.Graphics.FillEllipse(b, cx - 5, 8, 10, 10);
                TextRenderer.DrawText(e.Graphics, Text, LabelFont,
                    new Rectangle(37, 3, 108, 20), Color.FromArgb(33, 33, 33),
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            }
        }

        // Paint the text in two tones; WinForms' standard Button has only one ForeColor.
        private sealed class CountdownInstallButton : Button
        {
            public int SecondsLeft = 60;
            public bool ShowCountdown = true;
            public CountdownInstallButton()
            {
                Text = "";
                SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                         ControlStyles.OptimizedDoubleBuffer, true);
            }
            protected override void OnPaint(PaintEventArgs e)
            {
                base.OnPaint(e);
                string word = "INSTALL";
                string count = ShowCountdown ? " (" + SecondsLeft.ToString() + ")" : "";
                TextFormatFlags flags = TextFormatFlags.NoPadding | TextFormatFlags.SingleLine;
                Size first = TextRenderer.MeasureText(e.Graphics, word, Font, Size.Empty, flags);
                Size second = TextRenderer.MeasureText(e.Graphics, count, Font, Size.Empty, flags);
                int x = Math.Max(0, (ClientSize.Width - first.Width - second.Width) / 2);
                int y = Math.Max(0, (ClientSize.Height - Font.Height) / 2);
                TextRenderer.DrawText(e.Graphics, word, Font, new Point(x, y),
                    Color.FromArgb(15, 15, 15), flags);
                if (ShowCountdown)
                    TextRenderer.DrawText(e.Graphics, count, Font,
                        new Point(x + first.Width, y), Color.FromArgb(154, 154, 154), flags);
            }
        }

        private static string PromptInstallerPath(string defaultPath,
            out bool createShortcuts, out bool createUninstaller)
        {
            createShortcuts = true;
            createUninstaller = true;
            using (Form dialog = new Form())
            {
                dialog.Text = "__APP_NAME__";
                dialog.ClientSize = new Size(263, 154);
                dialog.FormBorderStyle = FormBorderStyle.FixedDialog;
                dialog.StartPosition = FormStartPosition.CenterScreen;
                dialog.MaximizeBox = false;
                dialog.MinimizeBox = false;
                dialog.BackColor = Color.FromArgb(249, 249, 249);
                dialog.Font = new Font("Segoe UI", 9F);
                try { dialog.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
                Label heading = new Label();
                heading.Text = "Select Unpacking Location";
                heading.Bounds = new Rectangle(11, 12, 242, 21);
                dialog.Controls.Add(heading);

                TextBox pathInput = new TextBox();
                pathInput.Text = defaultPath;
                pathInput.AutoSize = false;
                pathInput.Bounds = new Rectangle(11, 45, 215, 23);
                pathInput.BorderStyle = BorderStyle.FixedSingle;
                dialog.Controls.Add(pathInput);

                int panPosition = 0, panDirection = 1, panHold = 8;
                System.Windows.Forms.Timer pathPanTimer = new System.Windows.Forms.Timer();
                pathPanTimer.Interval = 155;
                Action syncPathPan = delegate
                {
                    bool overflowing = !string.IsNullOrEmpty(pathInput.Text) &&
                        TextRenderer.MeasureText(pathInput.Text, pathInput.Font).Width >
                            pathInput.ClientSize.Width - 12;
                    if (overflowing && pathInput.Visible && !pathInput.Focused)
                        pathPanTimer.Start();
                    else
                        pathPanTimer.Stop();
                };
                pathInput.TextChanged += delegate
                {
                    panPosition = 0; panDirection = 1; panHold = 8;
                    syncPathPan();
                };
                pathInput.Enter += delegate { pathPanTimer.Stop(); };
                pathInput.Leave += delegate { syncPathPan(); };
                pathInput.Resize += delegate { syncPathPan(); };
                dialog.Shown += delegate { syncPathPan(); };
                pathPanTimer.Tick += delegate
                {
                    if (panHold > 0) { panHold--; return; }
                    panPosition = Math.Max(0, Math.Min(pathInput.Text.Length, panPosition + panDirection));
                    pathInput.SelectionStart = panPosition;
                    pathInput.SelectionLength = 0;
                    if (panPosition == 0 || panPosition == pathInput.Text.Length)
                    {
                        panDirection = -panDirection;
                        panHold = 8;
                    }
                };
                dialog.FormClosed += delegate { pathPanTimer.Stop(); pathPanTimer.Dispose(); };
                Button browse = new Button();
                browse.Text = "...";
                browse.Bounds = new Rectangle(pathInput.Right, pathInput.Top, 25, pathInput.Height);
                browse.FlatStyle = FlatStyle.Popup;
                dialog.Controls.Add(browse);

                GrayToggle shortcuts = new GrayToggle("Create Shortcuts");
                shortcuts.Location = new Point(9, 82);
                dialog.Controls.Add(shortcuts);
                GrayToggle uninstaller = new GrayToggle("Create Uninstaller");
                uninstaller.Location = new Point(9, 109);
                dialog.Controls.Add(uninstaller);
                CountdownInstallButton install = new CountdownInstallButton();
                install.Font = new Font("Segoe UI", 8F, FontStyle.Bold);
                install.FlatStyle = FlatStyle.Popup;
                install.Bounds = new Rectangle(155, 94, 96, 29);
                dialog.Controls.Add(install);
                dialog.AcceptButton = install;

                string selectedPath = null;
                bool wantsShortcuts = true, wantsUninstaller = true;
                browse.Click += delegate
                {
                    using (FolderBrowserDialog picker = new FolderBrowserDialog())
                    {
                        picker.Description = "Select extraction folder";
                        string original = Environment.ExpandEnvironmentVariables(
                            pathInput.Text.Trim().Trim('"'));
                        if (Directory.Exists(original)) picker.SelectedPath = original;
                        if (picker.ShowDialog(dialog) == DialogResult.OK)
                            pathInput.Text = picker.SelectedPath;
                    }
                };
                install.Click += delegate
                {
                    try
                    {
                        string input = Environment.ExpandEnvironmentVariables(
                            pathInput.Text.Trim().Trim('"').Replace('/', '\\'));
                        if (string.IsNullOrWhiteSpace(input))
                            throw new ArgumentException("Extraction path cannot be empty.");
                        if (input.Length == 2 && input[1] == ':') input += "\\";
                        selectedPath = Path.GetFullPath(input);
                        wantsShortcuts = shortcuts.Checked;
                        wantsUninstaller = uninstaller.Checked;
                        dialog.DialogResult = DialogResult.OK;
                        dialog.Close();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(dialog, "Invalid extraction path: " + ex.Message,
                            dialog.Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }
                };
                // Only untouched dialogs auto-install, with the original defaults.
                // Any user input stops the countdown so a manual choice is never overridden.
                System.Windows.Forms.Timer unattendedTimer = new System.Windows.Forms.Timer();
                unattendedTimer.Interval = 1000;
                int remainingSeconds = 60;
                bool manuallySelected = false;
                Action stopAutoInstall = delegate
                {
                    manuallySelected = true;
                    unattendedTimer.Stop();
                    install.ShowCountdown = false;
                    install.Invalidate();
                };
                pathInput.KeyDown += delegate { stopAutoInstall(); };
                pathInput.MouseDown += delegate { stopAutoInstall(); };
                browse.MouseDown += delegate { stopAutoInstall(); };
                shortcuts.MouseDown += delegate { stopAutoInstall(); };
                uninstaller.MouseDown += delegate { stopAutoInstall(); };
                install.MouseDown += delegate { stopAutoInstall(); };
                dialog.MouseDown += delegate { stopAutoInstall(); };
                pathInput.TextChanged += delegate { stopAutoInstall(); };
                shortcuts.CheckedChanged += delegate { stopAutoInstall(); };
                uninstaller.CheckedChanged += delegate { stopAutoInstall(); };
                unattendedTimer.Tick += delegate
                {
                    if (manuallySelected || dialog.IsDisposed) { unattendedTimer.Stop(); return; }
                    remainingSeconds--;
                    install.SecondsLeft = Math.Max(0, remainingSeconds);
                    install.Invalidate();
                    if (remainingSeconds <= 0)
                    {
                        unattendedTimer.Stop();
                        install.PerformClick(); // same path validation as pressing INSTALL
                    }
                };
                dialog.Shown += delegate { unattendedTimer.Start(); };
                dialog.FormClosed += delegate { unattendedTimer.Stop(); unattendedTimer.Dispose(); };
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    createShortcuts = wantsShortcuts;
                    createUninstaller = wantsUninstaller;
                    return selectedPath;
                }
                return null;
            }
        }

''' if installer_mode else ""
        if installer_mode:
            installer_ui_code = installer_ui_code.replace("__APP_NAME__", prod_name_str)
        installer_prompt_code = '                if (installerSelected)\n                {\n                    string selectedPath = PromptInstallerPath(expanded, out createShortcuts, out createUninstaller);\n                    if (selectedPath == null)\n                        return; // User pressed Cancel or closed the dialog.\n                    expanded = selectedPath;\n                }\n' if installer_mode else ""
        installer_copy_code = '                if (installerSelected)\n                {\n                    string stagedPayload = Path.Combine(workTemp, "payload");\n                    if (createUninstaller &&\n                        (File.Exists(Path.Combine(stagedPayload, "Uninstall.exe")) ||\n                         File.Exists(Path.Combine(stagedPayload, "Uninstall.info"))))\n                        throw new IOException("Archive contains reserved uninstaller filenames.");\n                    InstallPayload(stagedPayload, targetDir, installedFiles, createdDirectories);\n                }\n\n' if installer_mode else ""
        installer_uninstall_code = '                if (installerSelected && createUninstaller)\n                {\n                    string uninstaller = Path.Combine(targetDir, "Uninstall.exe");\n                    string uninstallInfo = Path.Combine(targetDir, "Uninstall.info");\n                    ExtractResource("ByteWrapperUninstaller.exe", uninstaller);\n                    WriteUninstallInfo(uninstallInfo, targetDir, installedFiles,\n                        installedShortcuts, createdDirectories);\n                    RegisterWindowsUninstall(targetDir);\n                }\n\n' if installer_mode else ""
        installer_rollback_code = '                if (installerSelected)\n                    RollBackInstaller(targetDir, installedFiles, installedShortcuts,\n                        createdDirectories, createUninstaller);' if installer_mode else ""

        common_folder_guard = r"""        private static bool InsideFolder(string root, string path)
        {
            return Path.GetFullPath(path).StartsWith(
                Path.GetFullPath(root).TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }
""" if not installer_mode else ""

        cs_code = rf"""
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Drawing;
using System.Reflection;
using System.Diagnostics;
using System.ComponentModel;
using System.Threading;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Windows.Forms;
using System.Collections.Generic;
using System.Drawing.Drawing2D;
using Microsoft.Win32;

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
        private static readonly string RUN_TARGET = "{run_target_str}";
        private static readonly string RUN_ARGS = "{run_args_str}";
        private static readonly bool CREATE_SHORTCUT = {str(shortcut_active).lower()};
        private static readonly bool INSTALLER_MODE = {str(installer_mode).lower()};
        private static readonly string UNINSTALL_PACKAGE_ID = "{uninstall_id_str}";
        private static readonly string SHORTCUT_NAME = "{shortcut_name_str}";
        private static readonly string SHORTCUT_PATH = "{shortcut_path_str}";
        private static readonly string SHORTCUT_TARGET = "{shortcut_target_str}";
        private static readonly string SHORTCUT_ARGS = "{shortcut_args_str}";
        private static readonly string SHORTCUT_DESCRIPTION = "{shortcut_description_str}";
        private static readonly string INTERNAL_7Z_PW = "{internal_7z_pw_str}";
        private static readonly bool ASK_USER_PW = {ask_user_pw};
        private static readonly string EXPECTED_USER_PW_HASH = "{expected_user_pw_hash}";
        private static readonly bool HIDDEN_RUN = {hidden_run};
        private static readonly bool HIDDEN_SCRIPT_NEEDS_ADMIN = {hidden_script_needs_admin};
        private static readonly bool EXTRACT_ONLY = {extract_only};
        private static readonly bool INSTANCES = {instances};
        private static readonly bool SELF_REMOVE = {self_remove};
        private static readonly bool SHOW_PROGRESS = {show_progress};
        private const string ELEVATED_ARG_FLAG = "--bw-elevated";

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
            public int dwXSize2;
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

        private static string QuoteCmdValue(string val)
        {{
            StringBuilder sb = new StringBuilder("\"");
            int bs = 0;
            if (!string.IsNullOrEmpty(val))
            {{
                foreach (char c in val)
                {{
                    if (c == '\\')
                        bs++;
                    else if (c == '"')
                    {{
                        sb.Append('\\', bs * 2 + 1).Append('"');
                        bs = 0;
                    }}
                    else
                    {{
                        if (bs > 0) {{ sb.Append('\\', bs); bs = 0; }}
                        sb.Append(c);
                    }}
                }}
                if (bs > 0)
                    sb.Append('\\', bs * 2);
            }}
            sb.Append('"');
            return sb.ToString();
        }}

        private static bool VerifyUserPassword(string inputPw)
        {{
            using (SHA256 sha = SHA256.Create())
            {{
                string hex = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(inputPw ?? ""))).Replace("-", "");
                return string.Equals(hex, EXPECTED_USER_PW_HASH, StringComparison.OrdinalIgnoreCase);
            }}
        }}

        private static bool IsRunningAsAdministrator()
        {{
            try
            {{
                return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
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

            if (HIDDEN_RUN && HIDDEN_SCRIPT_NEEDS_ADMIN && !IsRunningAsAdministrator() &&
                Array.IndexOf(Environment.GetCommandLineArgs(), ELEVATED_ARG_FLAG) < 0)
            {{
                try
                {{
                    ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, ELEVATED_ARG_FLAG);
                    psi.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    psi.WindowStyle = ProcessWindowStyle.Hidden;
                    using (Process p = Process.Start(psi)) {{ }}
                }}
                catch {{ }}
                return;
            }}

            string runtime7zPw = INTERNAL_7Z_PW;
            if (ASK_USER_PW)
            {{
                string verifiedPw = null;
                for (int attempt = 1; attempt <= 3; attempt++)
                {{
                    string inputPw = PromptPassword();
                    if (inputPw == null)
                        return;
                    if (VerifyUserPassword(inputPw))
                    {{
                        verifiedPw = inputPw;
                        break;
                    }}
                    MessageBox.Show(
                        attempt < 3
                            ? ("Invalid password! Remaining attempts: " + (3 - attempt))
                            : "Invalid password!",
                        "{prod_name_str}",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                }}
                if (verifiedPw == null)
                    return;
                runtime7zPw = verifiedPw;
            }}

            bool createShortcuts = CREATE_SHORTCUT;
            bool createUninstaller = false;
            bool installerSelected = INSTALLER_MODE;
            bool rootCreated = false;
            string targetDir;
            try
            {{
                string configuredPath = EXTRACT_TO.Trim().Trim('"');
                string expanded = string.IsNullOrWhiteSpace(configuredPath)
                    ? Path.GetTempPath()
                    : Environment.ExpandEnvironmentVariables(configuredPath.Replace("/", "\\"));
                // Without any shortcut configuration, Extract Only uses the
                // configured directory directly and does not ask for a location.
                {installer_prompt_code}
                if (expanded.Length == 2 && expanded[1] == ':')
                    expanded += "\\";
                targetDir = Path.GetFullPath(expanded);
                if (installerSelected && createUninstaller &&
                    (File.Exists(Path.Combine(targetDir, "Uninstall.exe")) ||
                     File.Exists(Path.Combine(targetDir, "Uninstall.info"))))
                    throw new IOException("Uninstall.exe or Uninstall.info already exists at the destination.");
                rootCreated = !Directory.Exists(targetDir);
                Directory.CreateDirectory(targetDir);
            }}
            catch (Exception ex)
            {{
                if (!HIDDEN_RUN)
                    MessageBox.Show("Failed to prepare target directory: " + ex.Message,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }}

            string workTemp = Path.Combine(Path.GetTempPath(), "bw_rt_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            try
            {{
                Directory.CreateDirectory(workTemp);
            }}
            catch (Exception ex)
            {{
                if (!HIDDEN_RUN)
                    MessageBox.Show("Failed to create working directory: " + ex.Message,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }}

            Exception extractError = null;
            List<string> installedFiles = new List<string>();
            List<string> installedShortcuts = new List<string>();
            List<string> createdDirectories = new List<string>();
            if (installerSelected && rootCreated)
                createdDirectories.Add(targetDir);

            try
            {{
                Action<Action<int>> extractAction = delegate(Action<int> reportProgress)
                {{
                    try
                    {{
                        string sevenZExe = Path.Combine(workTemp, "7z.exe");
                        {extract_exe_line}
                        {extract_dll_line}

                        // Native 7-Zip encryption can be read directly from the EXE overlay.
                        string archivePath = Application.ExecutablePath;

                        bool trackProgress = (reportProgress != null);
                        string destination = installerSelected
                            ? Path.Combine(workTemp, "payload") : targetDir;
                        Directory.CreateDirectory(destination);
                        string outSwitch = destination.TrimEnd('\\');
                        if (outSwitch.Length == 2 && outSwitch[1] == ':')
                            outSwitch += "\\";
                        StringBuilder args = new StringBuilder();
                        args.Append(trackProgress ? "x -t7z -bso0 -bsp1 " : "x -t7z ");
                        args.Append(QuoteCmdValue(archivePath)).Append(" -o").Append(QuoteCmdValue(outSwitch)).Append(' ');
                        if (!string.IsNullOrEmpty(runtime7zPw))
                        {{
                            args.Append("-p").Append(QuoteCmdValue(runtime7zPw)).Append(' ');
                        }}
                        args.Append(INSTANCES ? "-aos -y" : "-aoa -y");

                        ProcessStartInfo psi7z = new ProcessStartInfo(sevenZExe, args.ToString());
                        psi7z.UseShellExecute = false;
                        psi7z.CreateNoWindow = true;
                        psi7z.WindowStyle = ProcessWindowStyle.Hidden;
                        psi7z.RedirectStandardOutput = trackProgress;

                        using (Process p = Process.Start(psi7z))
                        {{
                            if (p == null)
                                throw new InvalidOperationException("7-Zip extractor could not start.");

                            if (trackProgress)
                            {{
                                char[] readBuf = new char[512];
                                int charsRead;
                                while ((charsRead = p.StandardOutput.Read(readBuf, 0, readBuf.Length)) > 0)
                                {{
                                    for (int i = charsRead - 1; i >= 1; i--)
                                    {{
                                        if (readBuf[i] == '%' && (i + 1 == charsRead || char.IsWhiteSpace(readBuf[i + 1])))
                                        {{
                                            int d = i - 1;
                                            while (d >= 0 && readBuf[d] >= '0' && readBuf[d] <= '9') d--;
                                            int digits = i - 1 - d;
                                            if (digits >= 1 && digits <= 3)
                                            {{
                                                int s = d;
                                                while (s >= 0 && readBuf[s] == ' ') s--;
                                                if (s < 0 || readBuf[s] == '\r' || readBuf[s] == '\n' || readBuf[s] == '\b')
                                                {{
                                                    int pct = 0;
                                                    for (int k = d + 1; k < i; k++)
                                                        pct = pct * 10 + (readBuf[k] - '0');
                                                    reportProgress(Math.Min(100, pct));
                                                    break;
                                                }}
                                            }}
                                        }}
                                    }}
                                }}
                            }}

                            p.WaitForExit();
                            if (p.ExitCode != 0)
                                throw new InvalidDataException("7-Zip extraction failed with exit code " + p.ExitCode);
                            if (trackProgress)
                                reportProgress(100);
                        }}
                    }}
                    catch (Exception ex)
                    {{
                        extractError = ex;
                    }}
                }};

                // Extract Only with no shortcut configured has no progress UI.
                if (SHOW_PROGRESS && !HIDDEN_RUN && (!EXTRACT_ONLY || CREATE_SHORTCUT))
                {{
                    ProgressBar pbControl;
                    Label lblControl;
                    using (Form progressForm = CreateProgressForm(out pbControl, out lblControl))
                    {{
                        bool allowClose = false;
                        progressForm.FormClosing += delegate(object sender, FormClosingEventArgs e)
                        {{
                            if (!allowClose && e.CloseReason == CloseReason.UserClosing)
                                e.Cancel = true;
                        }};

                        int lastUiPct = -1;
                        Action<int> uiReporter = delegate(int val)
                        {{
                            int clamped = Math.Max(0, Math.Min(100, val));
                            if (clamped <= lastUiPct)
                                return;
                            lastUiPct = clamped;
                            try
                            {{
                                if (progressForm.IsHandleCreated && !progressForm.IsDisposed)
                                {{
                                    progressForm.BeginInvoke((MethodInvoker)delegate
                                    {{
                                        if (!pbControl.IsDisposed)
                                        {{
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
                                    progressForm.BeginInvoke((MethodInvoker)delegate
                                    {{
                                        allowClose = true;
                                        if (!pbControl.IsDisposed)
                                            pbControl.Value = 100;
                                        progressForm.Close();
                                    }});
                            }}
                            catch {{ }}
                        }});
                        worker.IsBackground = true;
                        progressForm.Shown += delegate {{ worker.Start(); }};
                        progressForm.ShowDialog();
                        if (worker.IsAlive)
                            worker.Join();
                    }}
                }}
                else
                {{
                    extractAction(null);
                }}

                if (extractError != null)
                    throw extractError;
                {installer_copy_code}

                if (createShortcuts)
                {{
                    try {{ CreatePackageShortcuts(targetDir,
                        installerSelected ? installedFiles : null,
                        installerSelected ? installedShortcuts : null); }}
                    catch (Exception shortcutEx)
                    {{
                        if (!HIDDEN_RUN)
                            MessageBox.Show("Shortcut creation failed: " + shortcutEx.Message,
                                "{prod_name_str}", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    }}
                }}

                {installer_uninstall_code}

                if (!EXTRACT_ONLY && !string.IsNullOrWhiteSpace(RUN_TARGET))
                {{
                    ExecuteRunFile(targetDir);
                }}
            }}
            catch (Exception ex)
            {{
                {installer_rollback_code}
                if (!HIDDEN_RUN)
                    MessageBox.Show("Package processing failed: " + ex.Message,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }}
            finally
            {{
                for (int i = 0; i < 4; i++)
                {{
                    try
                    {{
                        if (!Directory.Exists(workTemp))
                            break;
                        Directory.Delete(workTemp, true);
                        break;
                    }}
                    catch {{ }}
                }}
            }}

            if (SELF_REMOVE)
            {{
                SelfDeleteExe();
            }}
        }}


        {installer_support_code}
        {common_folder_guard}

        private static void CreatePackageShortcuts(string targetDir,
            List<string> createdPackageFiles, List<string> createdShortcutFiles)
        {{
            string relFile = Environment.ExpandEnvironmentVariables(
                SHORTCUT_TARGET.Trim().Trim('"').Replace("/", "\\"));
            string targetFile = Path.IsPathRooted(relFile)
                ? Path.GetFullPath(relFile)
                : Path.GetFullPath(Path.Combine(targetDir, relFile));
            if (!File.Exists(targetFile))
                throw new FileNotFoundException("Shortcut Run File not found", targetFile);
            if (createdPackageFiles != null && !InsideFolder(targetDir, targetFile))
                throw new IOException("Installer shortcut target must be inside the selected folder.");

            // Place the shortcut icon beside its Run File, using the same
            // filename stem. Example: bin\My App.exe -> bin\My App.ico.
            string iconPath = Path.Combine(Path.GetDirectoryName(targetFile),
                Path.GetFileNameWithoutExtension(targetFile) + ".ico");
            // Preserve an existing icon rather than overwriting a user-owned file.
            bool iconAlreadyExisted = File.Exists(iconPath);
            if (!iconAlreadyExisted || createdPackageFiles == null)
            {{
                ExtractResource("ByteWrapperShortcut.ico", iconPath);
                if (createdPackageFiles != null)
                    createdPackageFiles.Add(iconPath);
            }}

            string name = SHORTCUT_NAME.Trim();
            if (name.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                name = name.Substring(0, name.Length - 4);
            name += ".lnk";

            string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string startMenu = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
            string[] destinationFolders;
            if (string.Equals(SHORTCUT_PATH, "Desktop", StringComparison.OrdinalIgnoreCase))
                destinationFolders = new string[] {{ desktop }};
            else if (string.Equals(SHORTCUT_PATH, "Start Menu", StringComparison.OrdinalIgnoreCase))
                destinationFolders = new string[] {{ startMenu }};
            else if (string.Equals(SHORTCUT_PATH, "Start Menu & Desktop", StringComparison.OrdinalIgnoreCase))
                destinationFolders = new string[] {{ startMenu, desktop }};
            else
                destinationFolders = new string[] {{ Path.GetFullPath(
                    Environment.ExpandEnvironmentVariables(SHORTCUT_PATH.Trim().Trim('"'))) }};

            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null)
                throw new InvalidOperationException("Windows Script Host is not available.");
            object shell = Activator.CreateInstance(shellType);
            try
            {{
                foreach (string directory in destinationFolders)
                {{
                    Directory.CreateDirectory(directory);
                    string shortcutFile = Path.Combine(directory, name);
                    if (createdShortcutFiles != null && File.Exists(shortcutFile))
                        continue; // Installer mode must not overwrite existing shortcuts.
                    object link = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod,
                        null, shell, new object[] {{ shortcutFile }});
                    try
                    {{
                        Type linkType = link.GetType();
                        linkType.InvokeMember("TargetPath", BindingFlags.SetProperty,
                            null, link, new object[] {{ targetFile }});
                        linkType.InvokeMember("Arguments", BindingFlags.SetProperty,
                            null, link, new object[] {{ Environment.ExpandEnvironmentVariables(SHORTCUT_ARGS) }});
                        linkType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty,
                            null, link, new object[] {{ Path.GetDirectoryName(targetFile) }});
                        linkType.InvokeMember("IconLocation", BindingFlags.SetProperty,
                            null, link, new object[] {{ iconPath + ",0" }});
                        if (!string.IsNullOrWhiteSpace(SHORTCUT_DESCRIPTION))
                            linkType.InvokeMember("Description", BindingFlags.SetProperty,
                                null, link, new object[] {{ SHORTCUT_DESCRIPTION }});
                        linkType.InvokeMember("Save", BindingFlags.InvokeMethod,
                            null, link, new object[0]);
                        if (createdShortcutFiles != null)
                            createdShortcutFiles.Add(shortcutFile);
                    }}
                    finally
                    {{
                        if (link != null && Marshal.IsComObject(link))
                            Marshal.FinalReleaseComObject(link);
                    }}
                }}
            }}
            finally
            {{
                if (shell != null && Marshal.IsComObject(shell))
                    Marshal.FinalReleaseComObject(shell);
            }}
        }}

        private static void ExecuteRunFile(string targetDir)
        {{
            string relTarget = Environment.ExpandEnvironmentVariables(RUN_TARGET.Trim()).Replace("/", "\\");
            string args = Environment.ExpandEnvironmentVariables(RUN_ARGS.Trim());

            string directCand = Path.IsPathRooted(relTarget)
                ? Path.GetFullPath(relTarget)
                : Path.GetFullPath(Path.Combine(targetDir, relTarget));

            string resolvedFile = (!File.Exists(directCand) && !Path.IsPathRooted(relTarget) && relTarget.IndexOf('\\') < 0)
                ? relTarget
                : directCand;

            string workDir = Path.IsPathRooted(resolvedFile) ? Path.GetDirectoryName(resolvedFile) : targetDir;
            if (string.IsNullOrEmpty(workDir) || !Directory.Exists(workDir))
                workDir = targetDir;

            string suffix = string.IsNullOrEmpty(args) ? "" : (" " + args);
            string fileName = resolvedFile;
            string finalArgs = args;

            switch (Path.GetExtension(resolvedFile).ToLowerInvariant())
            {{
                case ".reg":
                    fileName = "regedit.exe";
                    finalArgs = (HIDDEN_RUN ? "/s \"" : "\"") + resolvedFile + "\"" + suffix;
                    break;
                case ".ps1":
                    fileName = "powershell.exe";
                    finalArgs = "-NoProfile -ExecutionPolicy Bypass " +
                        (HIDDEN_RUN ? "-NonInteractive -WindowStyle Hidden " : "") + "-File \"" + resolvedFile + "\"" + suffix;
                    break;
                case ".bat":
                case ".cmd":
                    fileName = "cmd.exe";
                    finalArgs = "/D /S /C \"\"" + resolvedFile + "\"" + suffix + "\"";
                    break;
                case ".msi":
                    fileName = "msiexec.exe";
                    finalArgs = "/i \"" + resolvedFile + "\"" + (HIDDEN_RUN ? " /qn /norestart" : "") + suffix;
                    break;
                case ".vbs":
                case ".js":
                case ".wsf":
                    fileName = "wscript.exe";
                    finalArgs = (HIDDEN_RUN ? "//B //Nologo \"" : "\"") + resolvedFile + "\"" + suffix;
                    break;
                case ".msc":
                    fileName = "mmc.exe";
                    finalArgs = "\"" + resolvedFile + "\"" + suffix;
                    break;
            }}

            RunNativeProcess(fileName, finalArgs, workDir, HIDDEN_RUN);
        }}

        private static string ResolveExecutableForCreateProcess(string fileName, string workDir)
        {{
            if (Path.IsPathRooted(fileName) && File.Exists(fileName))
                return Path.GetFullPath(fileName);
            string sys32 = Environment.SystemDirectory;
            string[] candidates = new string[] {{
                Path.Combine(workDir ?? "", fileName),
                Path.Combine(sys32, fileName),
                Path.Combine(sys32, @"WindowsPowerShell\v1.0\" + fileName),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), fileName)
            }};
            foreach (string cand in candidates)
                if (File.Exists(cand)) return Path.GetFullPath(cand);
            return null;
        }}

        private static bool TryRunHiddenNative(string fileName, string arguments, string workDir, out int win32Err)
        {{
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESHOWWINDOW;
            startup.wShowWindow = SW_HIDE;

            string resolvedExe = ResolveExecutableForCreateProcess(fileName, workDir);
            string cmdTarget = resolvedExe ?? fileName;
            StringBuilder commandBuffer = new StringBuilder(
                "\"" + cmdTarget + "\"" + (string.IsNullOrWhiteSpace(arguments) ? "" : " " + arguments)
            );
            PROCESS_INFORMATION processInfo;
            if (!CreateProcessW(resolvedExe, commandBuffer, IntPtr.Zero, IntPtr.Zero,
                false, CREATE_NO_WINDOW, IntPtr.Zero, workDir, ref startup, out processInfo))
            {{
                win32Err = Marshal.GetLastWin32Error();
                return false;
            }}

            win32Err = 0;
            if (processInfo.hThread != IntPtr.Zero)
                CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero)
                CloseHandle(processInfo.hProcess);
            return true;
        }}

        private static void RunNativeProcess(string fileName, string arguments, string workDir, bool hidden)
        {{
            int nativeErr = 0;
            if (hidden && TryRunHiddenNative(fileName, arguments, workDir, out nativeErr))
                return;

            if (nativeErr != 740)
            {{
                try
                {{
                    ProcessStartInfo psi = new ProcessStartInfo(fileName, arguments);
                    psi.WorkingDirectory = workDir;
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow = hidden;
                    psi.WindowStyle = hidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal;
                    using (Process p = Process.Start(psi))
                    {{
                        if (p == null)
                            throw new InvalidOperationException("Process could not be started: " + fileName);
                    }}
                    return;
                }}
                catch (Win32Exception ex)
                {{
                    nativeErr = ex.NativeErrorCode;
                }}
            }}

            ProcessStartInfo fallback = new ProcessStartInfo(fileName, arguments);
            fallback.WorkingDirectory = workDir;
            fallback.UseShellExecute = true;
            if (nativeErr == 740)
                fallback.Verb = "runas";
            fallback.WindowStyle = hidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal;
            using (Process p = Process.Start(fallback))
            {{
                if (p == null)
                    throw new InvalidOperationException("Process could not be started: " + fileName);
            }}
        }}

        private static void SelfDeleteExe()
        {{
            try
            {{
                string exePath = Application.ExecutablePath;
                ProcessStartInfo psi = new ProcessStartInfo(
                    "cmd.exe",
                    "/D /C for /L %i in (1,1,4) do @(del /f /q \"" + exePath + "\" >nul 2>&1 & if not exist \"" + exePath + "\" exit /b 0 & ping 127.0.0.1 -n 2 >nul)"
                );
                psi.WorkingDirectory = Path.GetTempPath();
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process p = Process.Start(psi)) {{ }}
            }}
            catch {{ }}
        }}

        private static void ExtractResource(string resName, string outPath)
        {{
            using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName))
            {{
                if (s == null)
                    throw new Exception("Resource not found: " + resName);
                if (resName.EndsWith(".bcj", StringComparison.OrdinalIgnoreCase))
                {{
                    using (MemoryStream restored = new MemoryStream())
                    {{
                        using (DeflateStream deflated = new DeflateStream(s, CompressionMode.Decompress))
                            deflated.CopyTo(restored);
                        byte[] buf = restored.GetBuffer();
                        int length = checked((int)restored.Length);
                        // Inverse of the optional E8/E9 transform used at build time.
                        for (int i = 0; i <= length - 5; )
                        {{
                            if (buf[i] == 0xE8 || buf[i] == 0xE9)
                            {{
                                unchecked
                                {{
                                    uint val = (uint)buf[i + 1] | ((uint)buf[i + 2] << 8) |
                                        ((uint)buf[i + 3] << 16) | ((uint)buf[i + 4] << 24);
                                    val -= (uint)i;
                                    buf[i + 1] = (byte)val;
                                    buf[i + 2] = (byte)(val >> 8);
                                    buf[i + 3] = (byte)(val >> 16);
                                    buf[i + 4] = (byte)(val >> 24);
                                }}
                                i += 5;
                            }}
                            else i++;
                        }}
                        using (FileStream output = File.Create(outPath))
                            output.Write(buf, 0, length);
                    }}
                }}
                else
                {{
                    using (FileStream fs = File.Create(outPath))
                    {{
                        if (resName.EndsWith(".gz", StringComparison.OrdinalIgnoreCase))
                        {{
                            using (GZipStream zipped = new GZipStream(s, CompressionMode.Decompress))
                                zipped.CopyTo(fs);
                        }}
                        else if (resName.EndsWith(".def", StringComparison.OrdinalIgnoreCase))
                        {{
                            using (DeflateStream deflated = new DeflateStream(s, CompressionMode.Decompress))
                                deflated.CopyTo(fs);
                        }}
                        else
                            s.CopyTo(fs);
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

            ProgressBar bar = new ProgressBar();
            bar.Minimum = 0;
            bar.Maximum = 100;
            bar.Value = 0;
            bar.Style = ProgressBarStyle.Blocks;
            bar.Bounds = new Rectangle(16, 40, 292, 18);
            f.Controls.Add(bar);

            pb = bar;
            return f;
        }}

        {installer_ui_code}

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

                return f.ShowDialog() == DialogResult.OK ? txt.Text : null;
            }}
        }}
    }}
}}
"""

        cs_file = os.path.join(work_dir, "Stub.cs")
        with open(cs_file, "w", encoding="utf-8-sig") as f:
            f.write(cs_code)

        # Compile stub inside work_dir with exact base_name so PE OriginalFilename is always base_name.exe
        work_exe = os.path.join(work_dir, f"{base_name}.exe")
        csc_cmd = [
            csc_path,
            "/nologo",
            "/target:winexe",
            "/optimize+",
            "/debug-",
            "/filealign:512",
            "/reference:System.dll",
            "/reference:System.Drawing.dll",
            "/reference:System.Windows.Forms.dll",
            f"/out:{work_exe}",
            f"/win32manifest:{manifest_path}",
            f"/resource:{exe_resource_path},{exe_resource_name}",
        ]
        if has_dll:
            csc_cmd.append(f"/resource:{dll_resource_path},{dll_resource_name}")
        if shortcut_icon_file:
            csc_cmd.append(f"/resource:{shortcut_icon_file},{shortcut_icon_resource}")
        if uninstall_resource_file:
            csc_cmd.append(f"/resource:{uninstall_resource_file},{uninstall_resource_name}")

        csc_cmd.append(f"/win32icon:{work_icon_path}")

        csc_cmd.append(cs_file)

        proc = self._start_process(
            csc_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if proc is None:
            return False, "Canceled by user."

        try:
            with proc:
                stdout, stderr = proc.communicate()
                ret_code = proc.returncode
        finally:
            with self._proc_lock:
                self._active_proc = None

        if self._cancelled:
            return False, "Canceled by user."

        if ret_code != 0 or not os.path.isfile(work_exe):
            return False, f"C# Stub Compilation Error:\n{stdout}\n{stderr}"

        self.progress.emit(70)

        # Move stub to .tmp staging file (avoids Windows Defender .exe write throttling) and append 7z payload
        try:
            shutil.move(work_exe, staging_exe)
            total_size = max(1, os.path.getsize(raw_7z_path))
            buf = bytearray(min(_IO_BUFFER_SIZE, total_size))
            view = memoryview(buf)

            with open(staging_exe, "ab") as output:
                if not (self.cfg["crypto"] or self.cfg["password"]):
                    source_bytes = cs_code.encode("utf-8")
                    packed_source = b""
                    if self.cfg["compress"]:
                        packed_source = zlib.compress(source_bytes, level=9)
                    if packed_source and len(packed_source) < len(source_bytes):
                        output.write(
                            b"\r\n" + _BW_ZLIB_SOURCE_START_MARKER + b"\r\n"
                            + packed_source
                            + b"\r\n" + _BW_ZLIB_SOURCE_END_MARKER + b"\r\n"
                        )
                    else:
                        output.write(
                            b"\r\n" + _BW_SOURCE_START_MARKER + b"\r\n"
                            + source_bytes
                            + b"\r\n" + _BW_SOURCE_END_MARKER + b"\r\n"
                        )

                processed = 0
                last_emitted = 70

                with open(raw_7z_path, "rb") as archive:
                    while not self._cancelled:
                        read_len = archive.readinto(buf)
                        if not read_len:
                            break
                        output.write(view[:read_len])
                        processed += read_len
                        mapped = 70 + (processed * 25) // total_size
                        if mapped != last_emitted:
                            last_emitted = mapped
                            self.progress.emit(mapped)

            if self._cancelled:
                return False, "Canceled by user."
        except Exception as exc:
            return False, str(exc)

        return True, staging_exe

    def run(self):
        work_dir = ""
        staging_exe = ""
        success = False
        message = ""
        try:
            self.progress.emit(5)

            seven_zip = self.cfg["seven_zip"]
            csc_path = self.cfg["csc_path"]
            base_name = self.cfg["base_name"]
            out_dir = self.cfg["output"]

            os.makedirs(out_dir, exist_ok=True)
            staging_exe = os.path.join(
                out_dir,
                f".bw_staging_{os.getpid()}_{uuid.uuid4().hex[:8]}.tmp"
            )

            self.progress.emit(20)

            work_dir = tempfile.mkdtemp(prefix=f"byte_wrapper_build_{os.getpid()}_")
            raw_7z = os.path.join(work_dir, "raw_package.7z")
            ret_7z = self.build_7z_archive(seven_zip, self.cfg["source"], raw_7z)
            if self._cancelled:
                message = "Canceled by user."
                return
            if ret_7z != 0:
                message = f"7-Zip compression failed (exit code {ret_7z})."
                return

            self.progress.emit(60)

            ok, msg = self.compile_csharp_sfx(
                csc_path, work_dir, raw_7z, seven_zip, staging_exe, base_name
            )
            if not ok:
                message = msg
                return

            with self._proc_lock:
                if self._cancelled:
                    message = "Canceled by user."
                    return
                target_exe = self._commit_staging_exe(staging_exe, base_name)
                staging_exe = ""
                self.output_exe_path = target_exe

            self.progress.emit(100)
            success = True
            message = f"Package successfully created at:\n{target_exe}"

        except Exception as e:
            message = f"Unexpected error: {str(e)}"
        finally:
            if staging_exe:
                _remove_temporary_path(staging_exe, False)
            if work_dir:
                _remove_temporary_path(work_dir, True)
            self.build_finished.emit(success, message)


# ==============================================================================
# 3. CUSTOM UI WIDGETS (HEADER DROP LOGO, ICON DROP BUTTON & SMART LINE EDIT)
# ==============================================================================
class _FileDropMixin:
    _EXTS: tuple[str, ...] = ()

    def dragEnterEvent(self, event):
        event.acceptProposedAction() if self.isEnabled() and _has_matching_url(event, self._EXTS) else event.ignore()

    def dragMoveEvent(self, event):
        event.acceptProposedAction() if self.isEnabled() and _has_matching_url(event, self._EXTS) else event.ignore()

    def dropEvent(self, event):
        if not self.isEnabled():
            event.ignore()
            return
        path = _first_dropped_path(event, self._EXTS)
        if path:
            self.fileDropped.emit(path)
            event.acceptProposedAction()
        else:
            event.ignore()


class SFXDropLogo(_FileDropMixin, QLabel):
    """Clickable header logo which also accepts local .exe/.sfx file drops."""
    fileDropped = pyqtSignal(str)
    clicked = pyqtSignal()
    _EXTS = (".exe", ".sfx")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setToolTip('Click to inspect an EXE/SFX or drop it here to open its config in your default editor.')

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
            event.accept()
        else:
            super().mousePressEvent(event)


class IconDropButton(_FileDropMixin, QPushButton):
    """Icon selector button which also accepts .ico, .png, .jpg, .jpeg, .jxl, .exe file drops."""
    fileDropped = pyqtSignal(str)
    _EXTS = (".ico", ".png", ".jpg", ".jpeg", ".jxl", ".exe")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)


class ScrollingLineEdit(QLineEdit):
    """Slowly pan overflowing text left/right when the field is not being edited.

    QLineEdit owns its horizontal viewport. Advancing the caret while unfocused
    scrolls that viewport without modifying the value or breaking normal editing.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._pan_cursor = 0
        self._pan_direction = 1
        self._pan_pause_ticks = 8
        self._pan_timer = QTimer(self)
        self._pan_timer.setInterval(155)
        self._pan_timer.timeout.connect(self._pan_step)
        self.textChanged.connect(self._pan_reset)

    def _sync_pan_timer(self):
        raw = self.text()
        displayed = raw if self.echoMode() == QLineEdit.EchoMode.Normal else ("•" * len(raw))
        should_pan = bool(
            raw and self.isVisible() and self.isEnabled() and not self.hasFocus()
            and self.fontMetrics().horizontalAdvance(displayed)
                > max(10, self.contentsRect().width() - 18)
        )
        if should_pan and not self._pan_timer.isActive():
            self._pan_timer.start()
        elif not should_pan and self._pan_timer.isActive():
            self._pan_timer.stop()

    def _pan_reset(self, _text=""):
        self._pan_cursor = 0
        self._pan_direction = 1
        self._pan_pause_ticks = 8
        if not self.hasFocus():
            self.setCursorPosition(0)
        self._sync_pan_timer()

    def _pan_step(self):
        if not self.isVisible() or not self.isEnabled() or self.hasFocus():
            self._pan_timer.stop()
            return
        raw = self.text()
        if self._pan_pause_ticks:
            self._pan_pause_ticks -= 1
            return
        self._pan_cursor = max(0, min(len(raw), self._pan_cursor + self._pan_direction))
        self.setCursorPosition(self._pan_cursor)
        if self._pan_cursor in (0, len(raw)):
            self._pan_direction *= -1
            self._pan_pause_ticks = 8

    def focusInEvent(self, event):
        super().focusInEvent(event)
        self._sync_pan_timer()

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        self._pan_reset()

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_pan_timer()

    def hideEvent(self, event):
        self._pan_timer.stop()
        super().hideEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_pan_timer()

    def changeEvent(self, event):
        super().changeEvent(event)
        if (hasattr(self, "_pan_timer") and event.type() in
                (QEvent.Type.FontChange, QEvent.Type.EnabledChange, QEvent.Type.StyleChange)):
            self._sync_pan_timer()


class SmartLineEdit(ScrollingLineEdit):
    """Supports direct typing, drag-and-drop, and right-click / empty-left-click preset menus."""
    def __init__(self, placeholder="", mode="source", parent_win=None):
        super().__init__(parent_win)
        self.setPlaceholderText(placeholder)
        self.mode = mode
        self.parent_win = parent_win
        self.setAcceptDrops(True)
        self.setFixedHeight(34)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if event.button() == Qt.MouseButton.LeftButton and (not self.text().strip() or self.mode == "shortcut_path"):
            QTimer.singleShot(0, self.open_selector)

    def contextMenuEvent(self, event):
        self.open_selector()

    def _format_run_file_selection(self, file_path: str) -> str:
        norm_file = expand_path(file_path, resolve_abs=True)
        if self.parent_win:
            src = self.parent_win._resolved_source
            src_kind = self.parent_win._source_kind
            if src_kind == "dir":
                rel = _relpath_if_within(norm_file, src)
                if rel and rel != ".":
                    return rel
            elif src_kind == "file" and (norm_file == src or _relpath_if_within(norm_file, src) == "."):
                return os.path.basename(norm_file)
        return norm_file

    def _set_selected_path(self, value: str):
        self.setText(value)
        if self.parent_win is not None and self.mode == "output":
            self.parent_win.validate_output_path(sync_replace=False)

    def open_selector(self):
        if not self.isEnabled():
            return

        menu = QMenu(self)
        act_folder = act_file = None
        presets = {}

        if self.mode == "source":
            act_folder = menu.addAction("1. Select Folder...")
            act_file = menu.addAction("2. Select File...")
        elif self.mode == "extract_to":
            act_folder = menu.addAction("1. Select Folder...")
            for label, val in (
                ("2. %Temp%", "%Temp%"),
                ("3. %SystemDrive%", "%SystemDrive%"),
                ("4. %SystemDrive%\\Program Files", "%SystemDrive%\\Program Files"),
                ("5. %SystemDrive%\\Program Files (x86)", "%SystemDrive%\\Program Files (x86)"),
                ("6. %SystemDrive%\\ProgramData", "%SystemDrive%\\ProgramData"),
                ("7. %UserProfile%\\Documents", "%UserProfile%\\Documents"),
                ("8. %AppData%", "%AppData%"),
                ("9. %LocalAppData%", "%LocalAppData%"),
            ):
                presets[menu.addAction(label)] = val
        elif self.mode == "output":
            act_folder = menu.addAction("1. Select Folder...")
            presets[menu.addAction("2. %UserProfile%\\Desktop")] = "%UserProfile%\\Desktop"
        elif self.mode in ("run_file", "shortcut_run_file"):
            act_file = menu.addAction("1. Select Executable / Script File...")
        elif self.mode == "shortcut_path":
            presets[menu.addAction("1. Desktop")] = "Desktop"
            presets[menu.addAction("2. Start Menu")] = "Start Menu"
            presets[menu.addAction("3. Start Menu && Desktop")] = "Start Menu & Desktop"

        menu.addSeparator()
        act_manual = menu.addAction(
            "Type Command / Path Manually"
            if self.mode in ("run_file", "shortcut_run_file") else "Type Manually"
        )

        action = menu.exec(self.mapToGlobal(QPoint(0, self.height())))
        if action is None:
            return
        if action in presets:
            self._set_selected_path(presets[action])
        elif action == act_folder:
            folder = QFileDialog.getExistingDirectory(self, "Select Folder")
            if folder:
                self._set_selected_path(expand_path(folder))
        elif action == act_file:
            start_dir = ""
            if self.mode in ("run_file", "shortcut_run_file") and self.parent_win:
                src = self.parent_win._resolved_source
                src_kind = self.parent_win._source_kind
                start_dir = src if src_kind == "dir" else (os.path.dirname(src) if src_kind == "file" else "")
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File", start_dir)
            if file_path:
                self._set_selected_path(
                    self._format_run_file_selection(file_path)
                    if self.mode in ("run_file", "shortcut_run_file") else expand_path(file_path)
                )
        elif action == act_manual:
            self.setFocus()

    def dragEnterEvent(self, event: QDragEnterEvent):
        if not self.isEnabled():
            event.ignore()
            return
        event.acceptProposedAction() if _has_matching_url(event) else super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if not self.isEnabled():
            event.ignore()
            return
        event.acceptProposedAction() if _has_matching_url(event) else super().dragMoveEvent(event)

    def dropEvent(self, event: QDropEvent):
        if not self.isEnabled():
            event.ignore()
            return
        dropped_path = _first_dropped_path(event)
        if dropped_path:
            if (self.parent_win is not None
                    and dropped_path.lower().endswith(".json")
                    and os.path.isfile(dropped_path)):
                self.parent_win.import_config_from_path(dropped_path)
                event.acceptProposedAction()
                return
            if self.mode in ("extract_to", "output") and os.path.isfile(dropped_path):
                if self.parent_win is not None:
                    self.parent_win._fail_start("Please drop a folder, not a file, into this field.")
                event.ignore()
                return
            if self.mode in ("run_file", "shortcut_run_file") and os.path.isdir(dropped_path):
                if self.parent_win is not None:
                    self.parent_win._fail_start("Run File must be an executable or script file, not a folder.")
                event.ignore()
                return
            if self.mode in ("run_file", "shortcut_run_file"):
                self._set_selected_path(self._format_run_file_selection(dropped_path))
            else:
                self._set_selected_path(dropped_path)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


# ==============================================================================
# 4. MAIN APPLICATION WINDOW (ORGANIZED BY GUI SECTIONS)
# ==============================================================================
class DraggableInfoDialog(QDialog):
    """Minimal frameless info popup; drag the empty surface to reposition it."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._drag_offset = None

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_offset = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._drag_offset = None
        super().mouseReleaseEvent(event)


class ByteWrapperWindow(QWidget):
    # --------------------------------------------------------------------------
    # 4.1. GUI INITIALIZATION, STYLES & WINDOW CONTROLS
    # --------------------------------------------------------------------------
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Byte Wrapper")
        self.setFixedSize(380, 680)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAcceptDrops(True)

        self.current_icon_bytes: bytes = b""
        self.current_icon_source: str = ""
        self.current_shortcut_icon_source: str = ""
        self.current_shortcut_icon_bytes: bytes = b""
        # Share the first non-default icon choice once, then keep icons independent.
        self._initial_icon_sync_done = False

        cleanup_temp_files_now()

        dpr = max(1.0, self.devicePixelRatioF())
        default_img = get_default_parcel_image()
        self.default_gui_icon = QIcon(pil_to_qpixmap(default_img, 256, dpr))
        self.default_btn_icon = QIcon(pil_to_qpixmap(default_img, 24, dpr))
        self.setWindowIcon(self.default_gui_icon)

        self._user_edited_name = False
        self._user_dont_replace = False
        self._tracked_source_path = ""
        self._resolved_source = ""
        self._source_kind = ""
        self._source_real = ""
        self._source_parent_real = ""
        self._source_exe_base = ""
        self._output_file_conflict = False
        self._last_run_cand = ""
        self._updating_ui = False
        self._status_dirty = False
        self._close_pending = False
        self._build_busy = False
        self.worker: SFXBuilderWorker | None = None
        self.last_output_exe: str = ""

        self._status_reset_timer = QTimer(self)
        self._status_reset_timer.setSingleShot(True)
        self._status_reset_timer.timeout.connect(self.reset_start_status)

        # Debounce PE icon extraction while Run File is being typed.
        self._run_file_icon_timer = QTimer(self)
        self._run_file_icon_timer.setSingleShot(True)
        self._run_file_icon_timer.timeout.connect(self._refresh_auto_icon_from_run_file)

        self._info_dialog = None
        self._info_links = {}
        self._info_animation = None
        self._info_hover_timer = QTimer(self)
        self._info_hover_timer.setSingleShot(True)
        self._info_hover_timer.setInterval(500)
        self._info_hover_timer.timeout.connect(self.show_info_dialog)
        self._info_hide_timer = QTimer(self)
        self._info_hide_timer.setSingleShot(True)
        self._info_hide_timer.setInterval(160)
        self._info_hide_timer.timeout.connect(self._maybe_hide_info)

        self.init_ui()
        self.apply_styles()

    @staticmethod
    def _seven_zip_availability() -> dict[str, bool]:
        """Check standard 7-Zip locations first, then the real script/EXE folder."""
        roots = []
        seen_roots = set()
        for path in (
            os.environ.get("ProgramW6432"),
            os.environ.get("ProgramFiles"),
            os.environ.get("ProgramFiles(x86)"),
            r"C:\Program Files",
            r"C:\Program Files (x86)",
        ):
            if path:
                normalized = os.path.normcase(path)
                if normalized not in seen_roots:
                    seen_roots.add(normalized)
                    roots.append(path)
        app_dir = _get_app_dir()
        result = {}
        for label, executable in (("7zip", "7z.exe"), ("7za", "7za.exe"), ("7zr", "7zr.exe")):
            # Do not treat binaries shipped beside the application as the default
            # installation: the application folder is intentionally the fallback.
            standard_locations = [os.path.join(root, "7-Zip", executable) for root in roots]
            standard_locations.extend(
                os.path.join(root, "7-Zip", "x64", executable) for root in roots
            )
            result[label] = (
                any(os.path.isfile(candidate) for candidate in standard_locations)
                or os.path.isfile(os.path.join(app_dir, executable))
            )
        return result

    def eventFilter(self, obj, event):
        if obj is getattr(self, "btn_info", None):
            if event.type() == QEvent.Type.Enter:
                self._info_hide_timer.stop()
                if self._info_dialog is None or not self._info_dialog.isVisible():
                    self._info_hover_timer.start()
                else:
                    self._animate_info(True)
            elif event.type() == QEvent.Type.Leave:
                self._info_hover_timer.stop()
                self._info_hide_timer.start()
        elif obj is self._info_dialog:
            if event.type() == QEvent.Type.Enter:
                self._info_hide_timer.stop()
                if self._info_dialog.isVisible():
                    self._animate_info(True)
            elif event.type() == QEvent.Type.Leave:
                self._info_hide_timer.start()
        return super().eventFilter(obj, event)

    def _cursor_over_info(self) -> bool:
        cursor = QCursor.pos()
        if self.btn_info.isVisible() and self.btn_info.rect().contains(
            self.btn_info.mapFromGlobal(cursor)
        ):
            return True
        popup = self._info_dialog
        if popup is not None and popup.isVisible():
            if getattr(popup, "_drag_offset", None) is not None:
                return True
            if popup.rect().contains(popup.mapFromGlobal(cursor)):
                return True
        return False

    def _maybe_hide_info(self):
        if not self._cursor_over_info():
            self._info_hover_timer.stop()
            self._animate_info(False)

    def _animate_info(self, appearing: bool):
        dialog = self._info_dialog
        if dialog is None or (not appearing and not dialog.isVisible()):
            return
        if self._info_animation is not None:
            self._info_animation.stop()
        anim = QPropertyAnimation(dialog, b"windowOpacity", self)
        anim.setDuration(180 if appearing else 200)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.setStartValue(dialog.windowOpacity())
        anim.setEndValue(1.0 if appearing else 0.0)
        self._info_animation = anim
        if not appearing:
            def hide_when_faded():
                if (self._info_animation is anim and not self._cursor_over_info()
                        and dialog.windowOpacity() <= 0.02):
                    dialog.hide()
            anim.finished.connect(hide_when_faded)
        anim.start()

    def show_info_dialog(self):
        """Present a fade-in hover popup without activating a separate window."""
        if not self._cursor_over_info():
            return
        dialog = self._info_dialog
        if dialog is None:
            dialog = DraggableInfoDialog(self)
            dialog.setObjectName("InfoDialog")
            dialog.setWindowFlags(Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint)
            dialog.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
            dialog.setFixedSize(182, 86)
            dialog.setStyleSheet("""
                QDialog#InfoDialog {
                    background-color: #0b1016;
                    border: 1px solid #263445;
                }
                QPushButton#InfoLinkBtn, QPushButton#InfoStatusBtn {
                    background: transparent;
                    border: none;
                    padding: 0px;
                    font-size: 12px;
                    text-decoration: none;
                }
                QLabel#InfoSeparator { color: #8792a0; background: transparent; }
            """)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(9, 14, 9, 11)
            layout.setSpacing(5)
            layout.addStretch(1)

            github = QPushButton("github", dialog)
            github.setObjectName("InfoLinkBtn")
            github.setFlat(True)
            github.setFixedHeight(20)
            github.setCursor(Qt.CursorShape.PointingHandCursor)
            github.setStyleSheet("QPushButton { color: #a0adbc; text-decoration: none; } "
                                 "QPushButton:hover { color: #d6dfe7; text-decoration: none; }")
            github.clicked.connect(lambda: QDesktopServices.openUrl(
                QUrl("https://github.com/EgeGurkan/ByteWrapper")))
            layout.addWidget(github, alignment=Qt.AlignmentFlag.AlignHCenter)

            link_row = QHBoxLayout()
            link_row.setSpacing(0)
            link_row.addStretch(1)
            for index, label in enumerate(("7zip", "7za", "7zr")):
                if index:
                    separator = QLabel(" - ", dialog)
                    separator.setObjectName("InfoSeparator")
                    link_row.addWidget(separator)
                link = QPushButton(label, dialog)
                link.setObjectName("InfoStatusBtn")
                link.setFlat(True)
                link.setFixedHeight(20)
                link.setCursor(Qt.CursorShape.PointingHandCursor)
                link.clicked.connect(lambda: QDesktopServices.openUrl(
                    QUrl("https://www.7-zip.org/download.html")))
                link_row.addWidget(link)
                self._info_links[label] = link
            link_row.addStretch(1)
            layout.addLayout(link_row)
            layout.addStretch(1)
            self._info_dialog = dialog
            dialog.installEventFilter(self)

        # Refresh at each appearance (not only at program startup).
        for name, found in self._seven_zip_availability().items():
            link = self._info_links[name]
            color = "#80d49a" if found else "#e37a80"
            hover_color = "#a8edbc" if found else "#ffabb1"
            link.setStyleSheet(
                "QPushButton { background: transparent; border: none; padding: 0; "
                f"color: {color}; text-decoration: none; }} "
                f"QPushButton:hover {{ color: {hover_color}; text-decoration: none; }}"
            )
            link.setToolTip("Found" if found else "Not found")

        # Popup touches the ? button edge so the mouse can move between them.
        top_right = self.btn_info.mapToGlobal(QPoint(self.btn_info.width(), self.btn_info.height()))
        dialog.move(top_right.x() - dialog.width(), top_right.y())
        if not dialog.isVisible():
            dialog.setWindowOpacity(0.0)
            dialog.show()
        self._info_hide_timer.stop()
        self._animate_info(True)

    @staticmethod
    def _make_section_label(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("SectionLabel")
        lbl.setFixedHeight(18)
        return lbl

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
        self.logo_label.clicked.connect(self.on_logo_clicked)
        logo_dpr = max(1.0, self.devicePixelRatioF())
        self.logo_label.setPixmap(pil_to_qpixmap(get_default_parcel_image(), 36, logo_dpr))
        self.logo_label.setFixedSize(36, 36)
        self.logo_label.setCursor(Qt.CursorShape.PointingHandCursor)
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

        btn_info = QPushButton("?")
        btn_info.setObjectName("WinControlBtn")
        btn_info.setFixedSize(26, 26)
        # Show the lightweight info popup after 0.5 seconds of hovering.
        # Avoid a native tooltip overlapping the popup.
        self.btn_info = btn_info
        btn_info.installEventFilter(self)

        btn_min = QPushButton("—")
        btn_min.setObjectName("WinControlBtn")
        btn_min.setFixedSize(26, 26)
        btn_min.clicked.connect(self.showMinimized)

        btn_close = QPushButton("✕")
        btn_close.setObjectName("WinCloseBtn")
        btn_close.setFixedSize(26, 26)
        btn_close.clicked.connect(self.close)

        header_layout.addWidget(btn_info, alignment=Qt.AlignmentFlag.AlignTop)
        header_layout.addWidget(btn_min, alignment=Qt.AlignmentFlag.AlignTop)
        header_layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignTop)
        main_layout.addLayout(header_layout)

        win_path_validator = QRegularExpressionValidator(
            QRegularExpression(r'^[^*?"<>|\x00-\x1f]*$'), self
        )

        # --- GROUP 1: PATH INPUT FIELDS ---
        main_layout.addWidget(self._make_section_label("Source Folder"))
        self.inp_source = SmartLineEdit("Select or drag and drop file or folder...", mode="source", parent_win=self)
        self.inp_source.setValidator(win_path_validator)
        self.inp_source.textChanged.connect(self.on_source_path_changed)
        main_layout.addWidget(self.inp_source)

        main_layout.addWidget(self._make_section_label("Extract To"))
        self.inp_extract = SmartLineEdit("Define extraction path...", mode="extract_to", parent_win=self)
        self.inp_extract.setValidator(win_path_validator)
        main_layout.addWidget(self.inp_extract)

        main_layout.addWidget(self._make_section_label("Run File"))
        self.inp_run = SmartLineEdit("Define run file path with parameters...", mode="run_file", parent_win=self)
        self.inp_run.textChanged.connect(self.on_run_file_changed)
        main_layout.addWidget(self.inp_run)

        main_layout.addWidget(self._make_section_label("Output"))
        self.inp_output = SmartLineEdit("Define save path...", mode="output", parent_win=self)
        self.inp_output.setValidator(win_path_validator)
        self.inp_output.textChanged.connect(self._sync_dont_replace_state)
        self.inp_output.editingFinished.connect(lambda: self.validate_output_path(sync_replace=False))
        main_layout.addWidget(self.inp_output)

        # --- GROUP 2: ICON, NAME, DESCRIPTION, VERSION ---
        main_layout.addWidget(self._make_section_label("Icon, Name, Description, Version"))
        nd_layout = QHBoxLayout()
        nd_layout.setContentsMargins(0, 0, 0, 0)
        nd_layout.setSpacing(6)

        self.btn_icon = IconDropButton(self)
        self.btn_icon.setObjectName("IconSelectBtn")
        self.btn_icon.setFixedSize(34, 34)
        self.btn_icon.setIcon(self.default_btn_icon)
        self.btn_icon.setIconSize(QSize(24, 24))
        self.btn_icon.clicked.connect(self.open_icon_menu)
        self.btn_icon.fileDropped.connect(self.apply_custom_icon_file)
        self.btn_icon.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.btn_icon.customContextMenuRequested.connect(self.reset_icon_to_default)
        self.btn_icon.setToolTip('Left-click or drop file: set icon. Right-click: restore default icon.')
        nd_layout.addWidget(self.btn_icon)

        win_filename_validator = QRegularExpressionValidator(
            QRegularExpression(r'^[^\\/:*?"<>|\x00-\x1f]*$'), self
        )

        self.inp_name = ScrollingLineEdit()
        self.inp_name.setPlaceholderText("Name...")
        self.inp_name.setFixedHeight(34)
        self.inp_name.setValidator(win_filename_validator)
        self.inp_name.textEdited.connect(self.on_name_manually_edited)
        self.inp_name.textChanged.connect(self._sync_dont_replace_state)
        nd_layout.addWidget(self.inp_name, stretch=3)

        self.inp_desc = ScrollingLineEdit()
        self.inp_desc.setPlaceholderText("Description...")
        self.inp_desc.setFixedHeight(34)
        self.inp_desc.setValidator(win_filename_validator)
        nd_layout.addWidget(self.inp_desc, stretch=3)

        self.inp_version = ScrollingLineEdit()
        self.inp_version.setObjectName("VersionInput")
        self.inp_version.setPlaceholderText("Version...")
        self.inp_version.setToolTip("Package file version (e.g. 1.0.0.0)")
        self.inp_version.setFixedHeight(34)
        ver_part = r"(?:6553[0-4]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})"
        ver_validator = QRegularExpressionValidator(
            QRegularExpression(rf"^(?:{ver_part}(?:\.{ver_part}){{0,3}})?$"), self.inp_version
        )
        self.inp_version.setValidator(ver_validator)
        nd_layout.addWidget(self.inp_version, stretch=3)

        main_layout.addLayout(nd_layout)

        # --- SHORTCUT CREATION (all three text fields are required together) ---
        main_layout.addWidget(self._make_section_label("Shortcut Creation"))
        shortcut_layout = QHBoxLayout()
        shortcut_layout.setContentsMargins(0, 0, 0, 0)
        shortcut_layout.setSpacing(6)

        self.btn_shortcut_icon = IconDropButton(self)
        self.btn_shortcut_icon.setObjectName("IconSelectBtn")
        self.btn_shortcut_icon.setFixedSize(34, 34)
        self.btn_shortcut_icon.setIcon(self.default_btn_icon)
        self.btn_shortcut_icon.setIconSize(QSize(24, 24))
        self.btn_shortcut_icon.setToolTip(
            "Left-click or drop file: set shortcut icon. Right-click: restore default icon."
        )
        self.btn_shortcut_icon.clicked.connect(self.open_shortcut_icon_menu)
        self.btn_shortcut_icon.fileDropped.connect(self.apply_shortcut_icon_file)
        self.btn_shortcut_icon.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.btn_shortcut_icon.customContextMenuRequested.connect(self.reset_shortcut_icon)
        shortcut_layout.addWidget(self.btn_shortcut_icon)

        self.inp_shortcut_name = ScrollingLineEdit()
        self.inp_shortcut_name.setPlaceholderText("Name...")
        self.inp_shortcut_name.setToolTip("Name")
        self.inp_shortcut_name.setFixedHeight(34)
        self.inp_shortcut_name.setValidator(win_filename_validator)
        shortcut_layout.addWidget(self.inp_shortcut_name, stretch=3)

        self.inp_shortcut_path = SmartLineEdit(
            "Path...", mode="shortcut_path", parent_win=self
        )
        self.inp_shortcut_path.setToolTip("Path: Desktop, Start Menu, both, or a custom folder")
        self.inp_shortcut_path.setValidator(win_path_validator)
        shortcut_layout.addWidget(self.inp_shortcut_path, stretch=3)

        self.inp_shortcut_run = SmartLineEdit(
            "Run File...", mode="shortcut_run_file", parent_win=self
        )
        self.inp_shortcut_run.setToolTip("Run File: file inside the extracted package")
        shortcut_layout.addWidget(self.inp_shortcut_run, stretch=3)
        main_layout.addLayout(shortcut_layout)

        # --- GROUP 3: OPTIONS ---
        main_layout.addWidget(self._make_section_label("Options"))
        opt_grid = QGridLayout()
        opt_grid.setContentsMargins(0, 2, 0, 4)
        opt_grid.setHorizontalSpacing(8)
        opt_grid.setVerticalSpacing(10)
        for col in range(3):
            opt_grid.setColumnStretch(col, 1)

        chk_defs = (
            ("chk_admin", "Run As Admin"),
            ("chk_hidden", "Hidden Run"),
            ("chk_dont_replace", "Don't Replace"),
            ("chk_extract_only", "Extract Only"),
            ("chk_self_remove", "Self Remove"),
            ("chk_progress_bar", "Progress Bar"),
            ("chk_compress", "Compress"),
            ("chk_crypto", "Crypto"),
            ("chk_instances", "Instances"),
        )
        all_checks = []
        for idx, (attr, label) in enumerate(chk_defs):
            chk = QCheckBox(label)
            chk.setFixedHeight(20)
            setattr(self, attr, chk)
            opt_grid.addWidget(chk, idx // 3, idx % 3)
            all_checks.append(chk)

        self.chk_dont_replace.toggled.connect(self.on_dont_replace_toggled)
        self.chk_extract_only.toggled.connect(self.on_extract_only_toggled)
        self.chk_hidden.toggled.connect(self.on_hidden_run_toggled)
        main_layout.addLayout(opt_grid)

        # --- GROUP 4: PROGRESS BAR, EXPORT / IMPORT, PASSWORD & START PROCESS ---
        main_layout.addSpacing(2)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(14)
        main_layout.addWidget(self.progress_bar)
        main_layout.addSpacing(4)

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

        self.inp_password = ScrollingLineEdit()
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

        fields = (
            self.inp_source, self.inp_extract, self.inp_run, self.inp_output,
            self.inp_name, self.inp_desc, self.inp_version, self.inp_password,
            self.inp_shortcut_name, self.inp_shortcut_path, self.inp_shortcut_run,
        )
        for field in fields:
            field.textChanged.connect(self.reset_start_status)
        for option in all_checks:
            option.toggled.connect(self.reset_start_status)
        self._build_controls = (
            self.logo_label, self.btn_icon, self.btn_shortcut_icon, self.btn_export, self.btn_import,
            *fields, *all_checks,
        )
        self._refresh_hidden_availability()

    def _set_build_busy(self, busy: bool):
        self._build_busy = busy
        self.setAcceptDrops(not busy)
        for control in self._build_controls:
            control.setEnabled(not busy)
        if not busy:
            self.inp_run.setEnabled(not self.chk_extract_only.isChecked())

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #0b1016;
                color: #e2e8f0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
            }
            QLabel {
                background: transparent;
            }
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

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and event.position().y() < 55:
            win_handle = self.windowHandle()
            if win_handle is not None:
                win_handle.startSystemMove()
            event.accept()

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self._close_pending = True
            self.btn_start.setEnabled(False)
            self.btn_start.setText("Canceling...")
            self.worker.cancel()
            event.ignore()
            return

        cleanup_temp_files_now(self.inp_output.text())
        event.accept()

    # --------------------------------------------------------------------------
    # 4.2. DRAG & DROP HANDLERS (1. TOP-LEFT EXE/SFX DROP, 2. JSON CONFIG DROP)
    # --------------------------------------------------------------------------
    def inspect_sfx_file(self, file_path: str):
        ok, result = process_file(expand_path(file_path))
        if not ok:
            QMessageBox.information(self, 'SFX Code Viewer', result)

    def on_logo_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            'Select SFX / EXE File',
            '',
            'Executable Files (*.exe *.sfx);;All Files (*.*)'
        )
        if file_path:
            self.inspect_sfx_file(file_path)

    def dragEnterEvent(self, event: QDragEnterEvent):
        event.acceptProposedAction() if not self._build_busy and _has_matching_url(event, (".json",)) else event.ignore()

    def dragMoveEvent(self, event):
        event.acceptProposedAction() if not self._build_busy and _has_matching_url(event, (".json",)) else event.ignore()

    def dropEvent(self, event: QDropEvent):
        if self._build_busy:
            event.ignore()
            return
        path = _first_dropped_path(event, (".json",))
        if path:
            self.import_config_from_path(path)
            event.acceptProposedAction()
        else:
            event.ignore()

    # --------------------------------------------------------------------------
    # 4.3. GROUP 1 HANDLERS: SOURCE FOLDER, EXTRACT TO, RUN FILE, OUTPUT
    # --------------------------------------------------------------------------
    def _update_source_cache(self, raw_text: str) -> str:
        expanded = expand_path(raw_text, resolve_abs=True) if raw_text.strip() else ""
        self._resolved_source = expanded
        self._source_kind = ""
        self._source_real = ""
        self._source_parent_real = ""
        self._source_exe_base = ""
        if expanded:
            if os.path.isdir(expanded):
                self._source_kind = "dir"
                try:
                    self._source_real = os.path.realpath(expanded)
                except OSError:
                    self._source_real = expanded
            elif os.path.isfile(expanded):
                self._source_kind = "file"
                try:
                    real_file = os.path.realpath(expanded)
                except OSError:
                    real_file = expanded
                self._source_real = real_file
                self._source_parent_real = os.path.normcase(os.path.dirname(real_file))
                stem, ext = os.path.splitext(os.path.basename(expanded))
                if ext.lower() == ".exe":
                    self._source_exe_base = os.path.normcase(_validate_package_name(stem) or "")
        return expanded

    def _sync_dont_replace_state(
        self, *_args, norm_output: str = "", output_resolved: bool = False
    ):
        if self._updating_ui:
            return
        conflict = False
        if self._source_kind == "file" and self._source_exe_base:
            pkg_base = _validate_package_name(self.inp_name.text())
            if pkg_base and os.path.normcase(pkg_base) == self._source_exe_base:
                out_dir = norm_output if output_resolved else expand_path(self.inp_output.text(), resolve_abs=True)
                if out_dir:
                    try:
                        conflict = os.path.normcase(os.path.realpath(out_dir)) == self._source_parent_real
                    except OSError:
                        conflict = False

        self._output_file_conflict = conflict
        target_checked = True if conflict else self._user_dont_replace
        if self.chk_dont_replace.isChecked() != target_checked:
            self._updating_ui = True
            try:
                self.chk_dont_replace.setChecked(target_checked)
            finally:
                self._updating_ui = False
        self.chk_dont_replace.setToolTip(
            "Enabled automatically to prevent overwriting the original source file."
            if conflict else ""
        )

    def validate_output_path(
        self, sync_replace: bool = True, norm_output: str = "", output_resolved: bool = False
    ) -> bool:
        if self._updating_ui:
            return True
        out = norm_output if output_resolved else expand_path(self.inp_output.text(), resolve_abs=True)
        if self._source_kind == "dir" and self._source_real and out and bool(_relpath_if_within(out, self._source_real)):
            self._updating_ui = True
            try:
                self.inp_output.clear()
            finally:
                self._updating_ui = False
            msg = "Output cannot be the source folder or one of its subfolders."
            self.inp_output.setToolTip(msg)
            self._sync_dont_replace_state(norm_output="", output_resolved=True)
            self._fail_start(msg)
            return False
        self.inp_output.setToolTip("")
        if sync_replace:
            self._sync_dont_replace_state(norm_output=out, output_resolved=True)
        return True

    def _auto_fill_name_from_source_dir(self):
        if not self._user_edited_name and not self.inp_name.text().strip():
            if self._source_kind == "dir" and self._resolved_source:
                folder_stem = _derive_auto_name_from_path(self._resolved_source, strip_ext=False)
                if folder_stem:
                    self._updating_ui = True
                    self.inp_name.setText(folder_stem)
                    self._updating_ui = False
                    self._sync_dont_replace_state()

    def on_source_path_changed(self, _text: str = ""):
        if self._updating_ui:
            return
        raw_text = self.inp_source.text()
        expanded = expand_path(raw_text, resolve_abs=True) if raw_text.strip() else ""
        normalized = os.path.normcase(expanded) if expanded else ""
        if normalized == self._tracked_source_path:
            return
        self._tracked_source_path = normalized
        self._run_file_icon_timer.stop()
        self._update_source_cache(raw_text)
        self._user_edited_name = False
        self._last_run_cand = ""

        self._updating_ui = True
        try:
            if self._source_kind == "file":
                base = os.path.basename(expanded)
                _, ext = os.path.splitext(base)
                self.inp_name.setText(_derive_auto_name_from_path(base, strip_ext=True))
                if ext.lower() in _RUNNABLE_EXTS:
                    self.inp_run.setText(base)
                    self._last_run_cand = base
                    if not self.apply_custom_icon_file(expanded):
                        self.reset_icon_to_default()
                else:
                    if self.inp_run.text():
                        self.inp_run.clear()
                    self.reset_icon_to_default()
            else:
                if self.inp_run.text():
                    self.inp_run.clear()
                folder_stem = (
                    _derive_auto_name_from_path(expanded, strip_ext=False)
                    if (self.chk_extract_only.isChecked() and self._source_kind == "dir")
                    else ""
                )
                if self.inp_name.text() != folder_stem:
                    self.inp_name.setText(folder_stem)
                self.reset_icon_to_default()
        finally:
            self._updating_ui = False
            self.validate_output_path(
                norm_output=expand_path(self.inp_output.text(), resolve_abs=True),
                output_resolved=True,
            )

    def on_run_file_changed(self, text: str):
        if self._updating_ui:
            return

        candidate, _ = _split_command_and_args(text.strip())
        # Argument edits alone must not override a manually selected name/icon.
        if candidate == self._last_run_cand:
            return
        self._last_run_cand = candidate
        self._run_file_icon_timer.stop()

        # A different Run File is a new package identity. Discard old overrides,
        # even when its name or icon was previously changed manually.
        self._user_edited_name = False
        self.reset_icon_to_default()
        stem = _derive_auto_name_from_path(candidate, strip_ext=True) if candidate else ""
        self._updating_ui = True
        try:
            self.inp_name.setText(stem)
        finally:
            self._updating_ui = False
        self._sync_dont_replace_state()

        if candidate:
            self._run_file_icon_timer.start(300)

    def _refresh_auto_icon_from_run_file(self):
        if self._updating_ui or not self.inp_run.isEnabled():
            return
        candidate, _ = _split_command_and_args(self.inp_run.text())
        if candidate and candidate == self._last_run_cand:
            self.set_icon_from_run_file()

    # --------------------------------------------------------------------------
    # 4.4. GROUP 2 HANDLERS: ICON, NAME, DESCRIPTION, VERSION
    # --------------------------------------------------------------------------
    def _set_slot_icon(
        self, for_shortcut: bool, source: str = "", icon_data: bytes = b"",
        pil_img: Image.Image | None = None
    ):
        """Update the active icon slot from already loaded bytes without re-reading the file."""
        button = self.btn_shortcut_icon if for_shortcut else self.btn_icon
        if for_shortcut:
            self.current_shortcut_icon_source = source
            self.current_shortcut_icon_bytes = icon_data
        else:
            self.current_icon_source = source
            self.current_icon_bytes = icon_data
        if pil_img is None:
            button.setIcon(self.default_btn_icon)
            button.setToolTip(
                "Left-click or drop file: set shortcut icon. Right-click: restore default icon."
                if for_shortcut else
                "Left-click or drop file: set icon. Right-click: restore default icon."
            )
        else:
            dpr = max(1.0, self.devicePixelRatioF())
            button.setIcon(QIcon(pil_to_qpixmap(pil_img, 24, dpr)))
            button.setToolTip(
                ("Shortcut icon loaded from: " if for_shortcut else "Icon loaded from: ") + source
            )

    def reset_icon_to_default(self, _pos=None, keep_tooltip: bool = False):
        had_custom = bool(self.current_icon_source or self.current_icon_bytes)
        previous_tooltip = self.btn_icon.toolTip() if keep_tooltip else ""
        self._set_slot_icon(False)
        if keep_tooltip:
            self.btn_icon.setToolTip(previous_tooltip)
        elif had_custom:
            self.btn_icon.setToolTip(
                'Default Byte Wrapper icon restored. Left-click or drop file to select another.'
            )
        self.reset_start_status()

    def open_icon_menu(self):
        self._show_icon_menu(for_shortcut=False)

    def open_shortcut_icon_menu(self):
        self._show_icon_menu(for_shortcut=True)

    def _show_icon_menu(self, for_shortcut: bool):
        """The main and shortcut icons expose the same selection actions."""
        target_button = self.btn_shortcut_icon if for_shortcut else self.btn_icon
        menu = QMenu(self)
        act_auto = menu.addAction("1. Get Automatically from Run File")
        act_select = menu.addAction("2. Select Icon...")
        act_imageres = menu.addAction("3. Select from imageres.dll...")
        act_shell32 = menu.addAction("4. Select from shell32.dll...")

        action = menu.exec(target_button.mapToGlobal(QPoint(0, target_button.height())))
        if action == act_auto:
            if for_shortcut:
                self.set_shortcut_icon_from_run_file()
            else:
                self.set_icon_from_run_file()
        elif action == act_select:
            self.select_icon_from_dialog(for_shortcut=for_shortcut)
        elif action == act_imageres:
            self.select_icon_from_system_dll("imageres.dll", for_shortcut=for_shortcut)
        elif action == act_shell32:
            self.select_icon_from_system_dll("shell32.dll", for_shortcut=for_shortcut)

    def _apply_icon_to_slot(
        self, file_path: str, icon_idx: int | None = None, for_shortcut: bool = False
    ) -> bool:
        button = self.btn_shortcut_icon if for_shortcut else self.btn_icon
        resolved_path, resolved_idx = _split_icon_source(file_path, icon_idx)
        if not resolved_path:
            button.setToolTip(
                "Shortcut icon file was not found." if for_shortcut else
                "Could not extract or convert the selected icon."
            )
            return False
        target_source = f"{resolved_path},{resolved_idx}" if resolved_idx is not None else resolved_path
        current_source = self.current_shortcut_icon_source if for_shortcut else self.current_icon_source
        current_bytes = self.current_shortcut_icon_bytes if for_shortcut else self.current_icon_bytes
        if target_source == current_source and current_bytes:
            return True
        icon_data, pil_img = extract_icon_from_file(resolved_path, resolved_idx)
        if not icon_data or pil_img is None:
            button.setToolTip(
                "Unable to read shortcut icon." if for_shortcut else
                "Could not extract or convert the selected icon."
            )
            return False

        other_default = not (
            (self.current_icon_source or self.current_icon_bytes) if for_shortcut
            else (self.current_shortcut_icon_source or self.current_shortcut_icon_bytes)
        )
        was_default = not (current_source or current_bytes)
        if not for_shortcut:
            self._run_file_icon_timer.stop()
        self._set_slot_icon(for_shortcut, target_source, icon_data, pil_img)
        if not self._updating_ui and not self._initial_icon_sync_done:
            self._initial_icon_sync_done = True
            if was_default and other_default:
                if for_shortcut:
                    self._run_file_icon_timer.stop()
                self._set_slot_icon(not for_shortcut, target_source, icon_data, pil_img)
        if not for_shortcut:
            label = (
                f"{os.path.basename(resolved_path)} (#{resolved_idx})"
                if resolved_idx is not None else os.path.basename(resolved_path)
            )
            self.btn_icon.setToolTip(f"Icon loaded from: {label}")
        self.reset_start_status()
        return True

    def apply_custom_icon_file(self, file_path: str, icon_idx: int | None = None) -> bool:
        return self._apply_icon_to_slot(file_path, icon_idx)

    def select_icon_from_system_dll(self, dll_name: str, for_shortcut: bool = False):
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        dll_path = os.path.join(sys32, dll_name)
        if not os.path.isfile(dll_path):
            return
        buf = ctypes.create_unicode_buffer(dll_path, 260)
        icon_idx = ctypes.c_int(0)
        if _SHELL32.PickIconDlg(int(self.winId()), buf, 260, ctypes.byref(icon_idx)):
            apply_icon = self.apply_shortcut_icon_file if for_shortcut else self.apply_custom_icon_file
            apply_icon(expand_path(buf.value), icon_idx.value)

    def _set_icon_from_run_slot(self, for_shortcut: bool):
        run_text = (
            self.inp_shortcut_run.text().strip() or self.inp_run.text().strip()
            if for_shortcut else self.inp_run.text()
        )
        cmd_part, _ = _split_command_and_args(run_text)
        target_file, _ = _resolve_run_file(
            self._resolved_source, cmd_part,
            source_resolved=True, source_kind=self._source_kind,
        )
        if not target_file:
            button = self.btn_shortcut_icon if for_shortcut else self.btn_icon
            button.setToolTip("Could not locate an icon from Run File or Source Folder.")
            return
        self._apply_icon_to_slot(target_file, for_shortcut=for_shortcut)

    def set_icon_from_run_file(self):
        self._set_icon_from_run_slot(False)

    def select_icon_from_dialog(self, for_shortcut: bool = False):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Icon or Application",
            "",
            "Icon & Executable Files (*.ico *.png *.jpeg *.jpg *.jxl *.exe)"
        )
        if file_path:
            apply_icon = self.apply_shortcut_icon_file if for_shortcut else self.apply_custom_icon_file
            apply_icon(expand_path(file_path))

    def reset_shortcut_icon(self, _pos=None):
        self._set_slot_icon(True)
        self.reset_start_status()

    def apply_shortcut_icon_file(self, file_path: str, icon_idx: int | None = None) -> bool:
        return self._apply_icon_to_slot(file_path, icon_idx, for_shortcut=True)

    def set_shortcut_icon_from_run_file(self):
        """Prefer Shortcut Run File; fall back to the main Run File if it is empty."""
        self._set_icon_from_run_slot(True)

    def on_name_manually_edited(self, text: str):
        self._user_edited_name = bool(text.strip())

    # --------------------------------------------------------------------------
    # 4.5. GROUP 3 HANDLERS: OPTIONS CHECKBOXES
    # --------------------------------------------------------------------------
    def on_dont_replace_toggled(self, checked: bool):
        if self._updating_ui:
            return
        if self._output_file_conflict:
            if not checked:
                self._updating_ui = True
                try:
                    self.chk_dont_replace.setChecked(True)
                finally:
                    self._updating_ui = False
            return
        self._user_dont_replace = checked

    def _ensure_default_extract_to(self):
        """Display the existing temporary extraction default when a mode needs it."""
        if not self.inp_extract.text().strip():
            self.inp_extract.setText("%Temp%")

    def on_extract_only_toggled(self, checked: bool):
        if self._updating_ui:
            return
        if checked:
            self._ensure_default_extract_to()
        if checked and self.chk_hidden.isChecked():
            self._updating_ui = True
            self.chk_hidden.setChecked(False)
            self._updating_ui = False
        self.inp_run.setEnabled(not checked)
        if checked:
            self._auto_fill_name_from_source_dir()
        self._refresh_hidden_availability()

    def on_hidden_run_toggled(self, checked: bool):
        if self._updating_ui:
            return
        if checked:
            self._ensure_default_extract_to()
        if checked and self.chk_extract_only.isChecked():
            self._updating_ui = True
            self.chk_extract_only.setChecked(False)
            self._updating_ui = False
            self.inp_run.setEnabled(True)
        self._refresh_hidden_availability()

    def _refresh_hidden_availability(self):
        extract_selected = self.chk_extract_only.isChecked()
        hidden_selected = self.chk_hidden.isChecked()

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

    # --------------------------------------------------------------------------
    # 4.6. GROUP 4 HANDLERS: EXPORT, IMPORT, PASSWORD & START PROCESS
    # --------------------------------------------------------------------------
    def collect_config(self, include_icon_bytes: bool = True) -> dict:
        pw = _validate_password_input(self.inp_password.text())
        cfg = {
            "source": self.inp_source.text(),
            "extract_to": self.inp_extract.text(),
            "run_file": self.inp_run.text(),
            "output": self.inp_output.text(),
            "name": self.inp_name.text(),
            "description": self.inp_desc.text(),
            "version": self.inp_version.text(),
            "icon_source": self.current_icon_source,
            "shortcut_icon_source": self.current_shortcut_icon_source,
            "shortcut_name": self.inp_shortcut_name.text(),
            "shortcut_path": self.inp_shortcut_path.text(),
            "shortcut_run_file": self.inp_shortcut_run.text(),
            "run_as_admin": self.chk_admin.isChecked(),
            "hidden_run": self.chk_hidden.isChecked(),
            "dont_replace": self.chk_dont_replace.isChecked(),
            "extract_only": self.chk_extract_only.isChecked(),
            "self_remove": self.chk_self_remove.isChecked(),
            "progress_bar": self.chk_progress_bar.isChecked(),
            "compress": self.chk_compress.isChecked(),
            "crypto": self.chk_crypto.isChecked(),
            "instances": self.chk_instances.isChecked(),
            "password": pw,
        }
        if include_icon_bytes:
            cfg["icon_bytes"] = self.current_icon_bytes
            cfg["shortcut_icon_bytes"] = self.current_shortcut_icon_bytes
        return cfg

    def export_config(self):
        try:
            export_data = self.collect_config(include_icon_bytes=False)
            _validate_metadata_fields(
                export_data["name"], export_data["description"], export_data["version"]
            )
        except ValueError as e:
            err_msg = str(e)
            self.btn_export.setToolTip(err_msg)
            self._fail_start(err_msg)
            return

        export_data["password"] = encrypt_password_for_export(export_data["password"])

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Export Configuration Script", "byte_wrapper_config.json", "JSON Script (*.json)"
        )
        if not save_path:
            return
        target_path = expand_path(save_path, resolve_abs=True)
        target_dir = os.path.dirname(target_path) or "."
        tmp_path = ""
        try:
            os.makedirs(target_dir, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=target_dir,
                prefix=".bw_cfg_",
                suffix=".tmp",
                delete=False,
            ) as f:
                tmp_path = f.name
                json.dump(export_data, f, indent=4, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target_path)
            tmp_path = ""
            self.btn_export.setToolTip("Configuration exported successfully.")
        except Exception as e:
            if tmp_path:
                _remove_temporary_path(tmp_path, False)
            err_msg = f"Failed to export configuration: {e}"
            self.btn_export.setToolTip(err_msg)
            self._fail_start(err_msg)

    def import_config_from_path(self, open_path: str):
        if not open_path:
            return
        try:
            with open(open_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if not isinstance(cfg, dict):
                raise ValueError("Configuration file must contain a JSON object.")

            str_vals: dict[str, str] = {}
            for key in _CFG_STR_KEYS:
                val = cfg.get(key, "")
                if not isinstance(val, str):
                    raise ValueError(f"Invalid type for '{key}': expected string.")
                str_vals[key] = val

            bool_vals: dict[str, bool] = {}
            for key in _CFG_BOOL_KEYS:
                val = cfg.get(key, False)
                if not isinstance(val, bool):
                    raise ValueError(f"Invalid type for '{key}': expected boolean.")
                bool_vals[key] = val

            if bool_vals["extract_only"] and bool_vals["hidden_run"]:
                raise ValueError("Cannot enable both 'extract_only' and 'hidden_run' in configuration.")

            for path_key in ("source", "extract_to", "output"):
                raw_p = str_vals[path_key].strip()
                if raw_p and _has_invalid_path_chars(expand_path(raw_p)):
                    raise ValueError(f"Invalid path characters in '{path_key}'.")

            ver_val = str_vals["version"].strip()
            name_val = str_vals["name"]
            desc_val = str_vals["description"]
            _, desc_val, _ = _validate_metadata_fields(name_val, desc_val, ver_val)
            pw_val = decrypt_password_from_import(str_vals["password"])
        except Exception as e:
            err_msg = f"Failed to import configuration: {e}"
            self.btn_import.setToolTip(err_msg)
            self._fail_start(err_msg)
            return

        self._run_file_icon_timer.stop()
        self._updating_ui = True
        try:
            run_val = str_vals["run_file"]
            src_val = str_vals["source"]
            extract_only = bool_vals["extract_only"]
            self._user_edited_name = bool(name_val.strip())
            expanded_src = self._update_source_cache(src_val)
            self._tracked_source_path = os.path.normcase(expanded_src) if expanded_src else ""

            cand, _ = _split_command_and_args(run_val)
            self._last_run_cand = cand
            if not name_val.strip():
                if cand:
                    name_val = _derive_auto_name_from_path(cand, strip_ext=True)
                elif self._source_kind == "file":
                    name_val = _derive_auto_name_from_path(expanded_src, strip_ext=True)
                elif extract_only and self._source_kind == "dir":
                    name_val = _derive_auto_name_from_path(expanded_src, strip_ext=False)

            self.inp_source.setText(src_val)
            self.inp_extract.setText(str_vals["extract_to"])
            self.inp_name.setText(name_val)
            self.inp_run.setText(run_val)
            self.inp_output.setText(str_vals["output"])
            self.inp_desc.setText(desc_val)
            self.inp_version.setText(ver_val)
            self.inp_shortcut_name.setText(str_vals["shortcut_name"])
            self.inp_shortcut_path.setText(str_vals["shortcut_path"])
            self.inp_shortcut_run.setText(str_vals["shortcut_run_file"])

            dont_replace_val = bool_vals["dont_replace"]
            self._user_dont_replace = dont_replace_val

            self.chk_admin.setChecked(bool_vals["run_as_admin"])
            self.chk_hidden.setChecked(bool_vals["hidden_run"])
            self.chk_dont_replace.setChecked(dont_replace_val)
            self.chk_extract_only.setChecked(extract_only)
            self.chk_self_remove.setChecked(bool_vals["self_remove"])
            self.chk_progress_bar.setChecked(bool_vals["progress_bar"])
            self.chk_compress.setChecked(bool_vals["compress"])
            self.chk_crypto.setChecked(bool_vals["crypto"])
            self.chk_instances.setChecked(bool_vals["instances"])
            self.inp_run.setEnabled(not extract_only)
            if extract_only or bool_vals["hidden_run"]:
                self._ensure_default_extract_to()
            self._refresh_hidden_availability()

            self.inp_password.setText(pw_val)

            raw_icon_src = str_vals["icon_source"].strip()
            if not raw_icon_src:
                self.reset_icon_to_default()
            elif not self.apply_custom_icon_file(raw_icon_src):
                self.reset_icon_to_default(keep_tooltip=True)

            shortcut_icon_src = str_vals["shortcut_icon_source"].strip()
            if not shortcut_icon_src or not self.apply_shortcut_icon_file(shortcut_icon_src):
                self.reset_shortcut_icon()
            self._initial_icon_sync_done = bool(
                self.current_icon_source or self.current_shortcut_icon_source
            )

            self.btn_import.setToolTip("")
        finally:
            self._updating_ui = False
            self.validate_output_path(
                norm_output=expand_path(self.inp_output.text(), resolve_abs=True),
                output_resolved=True,
            )
            self.reset_start_status()

    def import_config(self):
        open_path, _ = QFileDialog.getOpenFileName(
            self, "Import Configuration Script", "", "JSON Script (*.json)"
        )
        if open_path:
            self.import_config_from_path(open_path)

    def reset_start_status(self, *args):
        if not self._status_dirty or self._updating_ui:
            return
        self._status_dirty = False
        self._status_reset_timer.stop()
        self.btn_start.setText("Start Process")
        self.btn_start.setToolTip("")

    def _fail_start(self, reason: str):
        self._status_dirty = True
        self.btn_start.setText("Failed")
        self.btn_start.setToolTip(reason)
        self._status_reset_timer.start(5000)

    def open_completed_output_folder(self):
        target_exe = self.last_output_exe
        if target_exe and os.path.isfile(target_exe):
            try:
                subprocess.Popen(["explorer.exe", f"/select,{os.path.normpath(target_exe)}"])
                return
            except OSError:
                pass

        raw_out = expand_path(self.inp_output.text(), resolve_abs=True)
        if raw_out and os.path.isdir(raw_out):
            try:
                os.startfile(raw_out)
            except OSError:
                pass

    def start_process(self):
        if self.worker is not None and self.worker.isRunning():
            self.btn_start.setEnabled(False)
            self.btn_start.setText("Canceling...")
            self.worker.cancel()
            return

        if self.btn_start.text() == "Completed":
            self.open_completed_output_folder()
            return

        self._status_reset_timer.stop()
        self._status_dirty = False

        raw_source = self.inp_source.text().strip()
        raw_extract = self.inp_extract.text().strip()
        raw_run = self.inp_run.text().strip()
        raw_output = self.inp_output.text().strip()

        norm_source = self._update_source_cache(raw_source)
        if not norm_source or _has_invalid_path_chars(norm_source):
            self._fail_start("Source folder or file path is invalid.")
            return

        if not self._source_kind:
            self._fail_start("Source folder or file does not exist.")
            return

        extract_clean = raw_extract.strip('"').strip("'").strip()
        if extract_clean and _has_invalid_path_chars(extract_clean):
            self._fail_start("Extract To contains invalid path characters.")
            return

        extract_only = self.chk_extract_only.isChecked()
        cmd_part, run_args = ("", "") if extract_only else _split_command_and_args(raw_run)
        if not extract_only and _has_invalid_path_chars(cmd_part):
            self._fail_start("Run File cannot be empty or contain invalid path characters.")
            return

        shortcut_name = self.inp_shortcut_name.text().strip()
        shortcut_path = self.inp_shortcut_path.text().strip()
        raw_shortcut_run = self.inp_shortcut_run.text()
        shortcut_command, shortcut_arguments = _split_command_and_args(raw_shortcut_run)
        shortcut_fields = {
            "Name": shortcut_name,
            "Path": shortcut_path,
            "Run File": shortcut_command,
        }
        if any(shortcut_fields.values()) and not all(shortcut_fields.values()):
            missing = ", ".join(label for label, val in shortcut_fields.items() if not val)
            self._fail_start(f"Shortcut Creation is incomplete. Missing: {missing}.")
            return
        # Default icon is valid; all three text inputs activate shortcut creation.
        shortcut_active = all(shortcut_fields.values())
        if shortcut_active:
            shortcut_stem = shortcut_name[:-4] if shortcut_name.lower().endswith(".lnk") else shortcut_name
            if (not shortcut_stem.strip() or shortcut_stem.endswith((".", " "))
                    or _INVALID_FILENAME_CHARS_RE.search(shortcut_stem)
                    or _RESERVED_WIN_NAMES_RE.match(shortcut_stem)):
                self._fail_start("Shortcut Name contains invalid filename characters.")
                return
            if shortcut_path not in ("Desktop", "Start Menu", "Start Menu & Desktop") \
                    and _has_invalid_path_chars(shortcut_path):
                self._fail_start("Shortcut Path contains invalid path characters.")
                return
            if _has_invalid_path_chars(shortcut_command):
                self._fail_start("Shortcut Run File contains invalid path characters.")
                return

        norm_output = expand_path(raw_output, resolve_abs=True)
        if not norm_output:
            self._fail_start("Output directory path cannot be empty.")
            return

        out_drive, _ = os.path.splitdrive(norm_output)
        if _has_invalid_path_chars(norm_output) or (out_drive and not os.path.exists(out_drive + "\\")):
            self._fail_start("Output directory path is invalid.")
            return

        if os.path.isfile(norm_output):
            self._fail_start("Output path cannot be an existing file.")
            return

        if not self.validate_output_path(
            sync_replace=True, norm_output=norm_output, output_resolved=True
        ):
            return

        raw_name = self.inp_name.text()
        raw_desc_input = self.inp_desc.text()
        raw_version = self.inp_version.text()
        try:
            base_name, raw_desc, parsed_ver = _validate_metadata_fields(
                raw_name, raw_desc_input, raw_version
            )
            password = _validate_password_input(self.inp_password.text())
        except ValueError as e:
            self._fail_start(str(e))
            return

        seven_zip = SFXBuilderWorker.find_7zip()
        if not seven_zip:
            self._fail_start("7-Zip (7z.exe) was not found! Please make sure 7-Zip is installed.")
            return

        csc_path = SFXBuilderWorker.find_csc()
        if not csc_path:
            self._fail_start("Windows .NET C# compiler (csc.exe) was not found!")
            return

        cfg = {
            "source": norm_source,
            "source_kind": self._source_kind,
            "extract_to": extract_clean,
            "run_file": raw_run,
            "output": norm_output,
            "name": raw_name,
            "description": raw_desc,
            "version": raw_version,
            "icon_source": self.current_icon_source,
            "shortcut_icon_source": self.current_shortcut_icon_source,
            "shortcut_name": shortcut_name,
            "shortcut_path": shortcut_path,
            "shortcut_run_file": raw_shortcut_run,
            "run_as_admin": self.chk_admin.isChecked(),
            "hidden_run": self.chk_hidden.isChecked(),
            "dont_replace": self.chk_dont_replace.isChecked(),
            "extract_only": extract_only,
            "self_remove": self.chk_self_remove.isChecked(),
            "progress_bar": self.chk_progress_bar.isChecked(),
            "compress": self.chk_compress.isChecked(),
            "crypto": self.chk_crypto.isChecked(),
            "instances": self.chk_instances.isChecked(),
            "password": password,
            "icon_bytes": self.current_icon_bytes,
            "shortcut_icon_bytes": self.current_shortcut_icon_bytes,
            "cmd_part": cmd_part,
            "run_args": run_args,
            "base_name": base_name,
            "parsed_version": parsed_ver,
            "seven_zip": seven_zip,
            "csc_path": csc_path,
            "shortcut_active": bool(shortcut_active),
            "shortcut_command": shortcut_command if shortcut_active else "",
            "shortcut_args": shortcut_arguments if shortcut_active else "",
        }

        self.btn_start.setEnabled(True)
        self.btn_start.setText("Cancel")
        self.btn_start.setToolTip("")
        self.progress_bar.setValue(0)

        self.worker = SFXBuilderWorker(cfg)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.build_finished.connect(self.on_process_finished)
        self.worker.finished.connect(self.on_worker_thread_finished)
        self._set_build_busy(True)
        self.worker.start()

    def on_process_finished(self, success: bool, message: str):
        if self._close_pending:
            return

        self._status_dirty = True
        was_cancelled = self.worker is not None and self.worker._cancelled
        if was_cancelled:
            self.progress_bar.setValue(0)
            self.btn_start.setText("Canceled")
            self.btn_start.setToolTip("")
            self._status_reset_timer.start(5000)
            return

        if success:
            if self.worker is not None:
                self.last_output_exe = self.worker.output_exe_path
            self.btn_start.setText("Completed")
            self.btn_start.setToolTip(f"Click to open output folder:\n{self.last_output_exe}")
        else:
            self.progress_bar.setValue(0)
            self.btn_start.setText("Failed")
            self.btn_start.setToolTip(message or "Package build failed.")
            self._status_reset_timer.start(5000)

    def on_worker_thread_finished(self):
        if self._close_pending:
            self.close()
            return
        self._set_build_busy(False)
        self.btn_start.setEnabled(True)


if __name__ == "__main__":
    if not _acquire_single_instance_lock():
        sys.exit(0)
    app = QApplication(sys.argv)
    win = ByteWrapperWindow()
    win.show()
    sys.exit(app.exec())