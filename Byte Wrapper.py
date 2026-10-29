import os
import re
import sys
import json
import uuid
import struct
import base64
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
# Check Components # py -c "from PyQt6.QtWidgets import QApplication; from PIL import Image; import pillow_jxl; print('All dependencies OK')"
# Compile # py -m PyInstaller --noconfirm --clean --onefile --windowed --name "Byte Wrapper" --icon "Byte.ICO" --collect-all pillow_jxl "Byte Wrapper.py"


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
    Qt, QPoint, QThread, pyqtSignal, QSize, QTimer, QRegularExpression
)
from PyQt6.QtGui import (
    QIcon, QImage, QPixmap, QDragEnterEvent, QDropEvent, QRegularExpressionValidator
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

_BW_SOURCE_START_MARKER = b";!@ByteWrapperSource@UTF-8!"
_BW_SOURCE_END_MARKER = b";!@ByteWrapperSourceEnd@!"
_BW_HEADER_SCAN_LIMIT = 12 * 1024 * 1024
_IO_BUFFER_SIZE = 16 * 1024 * 1024

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
_PCT_RE = re.compile(rb"(\d{1,3})%")

_CFG_STR_KEYS = (
    "source", "extract_to", "run_file", "output",
    "name", "description", "version", "icon_source", "password",
)
_CFG_BOOL_KEYS = (
    "run_as_admin", "hidden_run", "dont_replace", "extract_only",
    "self_remove", "progress_bar", "compress", "crypto", "instances",
)

SECRET_EXPORT_KEY = b"ByteWrapper_Config_Cipher_Key"
_CACHED_TOOL_PATHS: dict[str, str] = {}

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_ENUMRESNAMEPROCW = ctypes.WINFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t
)
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


def _derive_auto_name(stem: str) -> str:
    cleaned = (stem or "").strip()
    return cleaned if (cleaned and _validate_package_name(cleaned) is not None) else ""


def _derive_auto_name_from_path(path_str: str, strip_ext: bool = True) -> str:
    base = os.path.basename(path_str.replace("/", "\\"))
    stem = os.path.splitext(base)[0] if strip_ext else base
    return _derive_auto_name(stem)


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


def _output_conflicts_with_source(source_path: str, output_path: str, resolved: bool = False) -> bool:
    source = source_path if resolved else expand_path(source_path, resolve_abs=True)
    output = output_path if resolved else expand_path(output_path, resolve_abs=True)
    if not source or not output or not os.path.isdir(source):
        return False
    return bool(_relpath_if_within(output, source))


def _single_file_conflicts_with_output(
    source_path: str, output_path: str, package_name: str, resolved: bool = False
) -> bool:
    """Return True when source is a single file, output is its parent folder, and package name matches."""
    source = source_path if resolved else expand_path(source_path, resolve_abs=True)
    output = output_path if resolved else expand_path(output_path, resolve_abs=True)
    if not source or not output:
        return False
    try:
        src_stem = os.path.splitext(os.path.basename(source))[0]
        src_base = _validate_package_name(src_stem)
        pkg_base = _validate_package_name(package_name)
        if not src_base or not pkg_base or os.path.normcase(src_base) != os.path.normcase(pkg_base):
            return False
        if not os.path.isfile(source):
            return False
        src_dir = os.path.normcase(os.path.realpath(os.path.dirname(source)))
        out_dir = os.path.normcase(os.path.realpath(output))
        return src_dir == out_dir
    except (OSError, ValueError):
        return False


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
        if not (part.isascii() and part.isdigit()):
            return None
        val = int(part)
        if val > 65534:
            return None
        normalized.append(str(val))
    while len(normalized) < 4:
        normalized.append("0")
    return ".".join(normalized), cleaned


def _remove_path_4_steps(path: str, is_dir: bool = False):
    """Attempt to remove a specific temporary path up to 4 times without scanning directories."""
    if not path:
        return
    for _ in range(4):
        try:
            if is_dir:
                if os.path.isdir(path):
                    shutil.rmtree(path)
            elif os.path.lexists(path):
                os.unlink(path)
            return
        except OSError:
            pass


def cleanup_temp_files_now(output_dir: str = ""):
    """Cleanup leftover Byte Wrapper preview files, build folders, and staging files."""
    try:
        with os.scandir(tempfile.gettempdir()) as entries:
            for entry in entries:
                name_l = entry.name.lower()
                if name_l.startswith("byte_wrapper_code_") and name_l.endswith(".txt"):
                    _remove_path_4_steps(entry.path, False)
                elif name_l.startswith("byte_wrapper_build_") and entry.is_dir(follow_symlinks=False):
                    _remove_path_4_steps(entry.path, True)
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
                        _remove_path_4_steps(entry.path, False)
        except OSError:
            pass


def process_file(file_path):
    """Open 7-Zip SFX configs or Byte Wrapper's embedded C# source in the default viewer."""
    cleanup_temp_files_now()
    sources = (
        (b';!@Install@!UTF-8!', b';!@InstallEnd@!', '7-Zip SFX config'),
        (b';!@Install@!', b';!@InstallEnd@!', '7-Zip SFX config'),
        (_BW_SOURCE_START_MARKER, _BW_SOURCE_END_MARKER, 'Byte Wrapper generated C# source'),
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
        for start_marker, end_marker, description in sources:
            start_idx = data.find(start_marker)
            if start_idx < 0:
                continue
            end_idx = data.find(end_marker, start_idx + len(start_marker))
            if end_idx < 0 or end_idx - start_idx > 2 * 1024 * 1024:
                continue
            content = data[start_idx:end_idx + len(end_marker)].decode('utf-8-sig', errors='replace')
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
            return _xor_cipher(raw_bytes).decode("utf-8")
        except Exception as exc:
            raise ValueError("Corrupted encrypted password data.") from exc
    return cipher_text


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


def _locate_run_file_in_source(source_path: str, cmd_part: str, source_resolved: bool = False) -> str:
    src = source_path if source_resolved else expand_path(source_path, resolve_abs=True)
    if not src:
        return ""
    if not cmd_part:
        return src if os.path.isfile(src) else ""
    cand = expand_path(cmd_part)
    if os.path.isabs(cand) and os.path.isfile(cand):
        return os.path.abspath(cand)
    if os.path.isdir(src):
        direct = os.path.join(src, cand.lstrip("\\/"))
        if os.path.isfile(direct):
            return os.path.abspath(direct)
    elif os.path.isfile(src) and os.path.normcase(cand) == os.path.normcase(os.path.basename(src)):
        return src
    return ""


def _package_run_target(source_path: str, cmd_part: str, resolved_run_path: str) -> str:
    """Only rewrite files actually included in the package to relative paths."""
    target = cmd_part
    if resolved_run_path:
        if os.path.isfile(source_path) and _relpath_if_within(resolved_run_path, source_path):
            target = os.path.basename(source_path)
        elif os.path.isdir(source_path):
            rel = _relpath_if_within(resolved_run_path, source_path)
            if rel and rel != ".":
                target = rel
            elif not os.path.isabs(expand_path(cmd_part)):
                target = resolved_run_path
        elif not os.path.isabs(expand_path(cmd_part)):
            target = resolved_run_path
    return target.replace("/", "\\")


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


def build_multi_ico_bytes(master_img: Image.Image) -> bytes:
    """Convert a PIL image into multi-resolution Windows .ico bytes in memory."""
    try:
        src = _to_square_rgba(master_img)
        buf = io.BytesIO()
        src.save(
            buf,
            format="ICO",
            sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)],
        )
        return buf.getvalue()
    except Exception:
        return b""


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


def get_default_parcel_image() -> Image.Image:
    global _DEFAULT_PARCEL_IMAGE
    if _DEFAULT_PARCEL_IMAGE is None:
        _DEFAULT_PARCEL_IMAGE = _render_parcel_canvas()
    return _DEFAULT_PARCEL_IMAGE


def get_default_sfx_icon_bytes() -> bytes:
    global _DEFAULT_SFX_ICON_BYTES
    if not _DEFAULT_SFX_ICON_BYTES:
        _DEFAULT_SFX_ICON_BYTES = build_multi_ico_bytes(get_default_parcel_image())
    return _DEFAULT_SFX_ICON_BYTES


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
    img = _to_square_rgba(pil_img)
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


def _find_executable(candidates: tuple[str, ...], cmd_name: str) -> str:
    cached = _CACHED_TOOL_PATHS.get(cmd_name)
    if cached and os.path.isfile(cached):
        return cached
    for cand in candidates:
        if os.path.isfile(cand):
            _CACHED_TOOL_PATHS[cmd_name] = cand
            return cand
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
        return _find_executable(
            (
                r"C:\Program Files\7-Zip\7z.exe",
                r"C:\Program Files (x86)\7-Zip\7z.exe",
            ),
            "7z",
        )

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

    def _get_source_total_size(self, source_path: str) -> int:
        """Scan source size up to DICT_SCAN_CAP_BYTES (65 MB) in a single scandir pass."""
        if os.path.isfile(source_path):
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
        cmd = [seven_zip, "a", "-bsp1"]

        if self.cfg["compress"]:
            dict_flag = self._select_7z_dict_flag(self._get_source_total_size(source_path))
            cmd.extend(["-t7z", "-mx=9", "-m0=lzma2", dict_flag, "-mfb=64", "-ms=16g", "-mmt=on"])
        else:
            cmd.extend(["-t7z", "-mx=0", "-mmt=on"])

        if self._archive_7z_pw:
            cmd.extend([f"-p{self._archive_7z_pw}", "-mhe=on"])

        cmd.extend(["-y", archive_path, "--"])
        cmd.append(os.path.join(source_path, "*") if os.path.isdir(source_path) else source_path)

        proc = self._start_process(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW
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
                return proc.wait()
        finally:
            with self._proc_lock:
                self._active_proc = None

    def compile_csharp_sfx(
        self, csc_path: str, work_dir: str, raw_7z_path: str,
        seven_zip: str, staging_exe: str, base_name: str
    ) -> tuple[bool, str]:
        seven_zip_dll = os.path.join(os.path.dirname(seven_zip), "7z.dll")
        has_dll = os.path.isfile(seven_zip_dll)

        source_path = self.cfg["source"]
        cmd_part = self.cfg["cmd_part"]
        run_args_raw = self.cfg["run_args"]

        resolved_run_path = (
            "" if self.cfg["extract_only"]
            else _locate_run_file_in_source(source_path, cmd_part, source_resolved=True)
        )
        self_elevating = (
            _looks_like_self_elevating_script(resolved_run_path)
            if (self.cfg["hidden_run"] and not self.cfg["run_as_admin"]) else False
        )
        run_target_rel = _package_run_target(source_path, cmd_part, resolved_run_path)

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

        ask_user_pw = "true" if self.cfg["password"] else "false"
        expected_user_pw_hash = cs_escape(self._expected_user_pw_hash)
        internal_7z_pw_str = cs_escape(self._stub_embedded_7z_pw)

        hidden_run = "true" if self.cfg["hidden_run"] else "false"
        hidden_script_needs_admin = "true" if self_elevating else "false"
        extract_only = "true" if self.cfg["extract_only"] else "false"
        instances = "true" if self.cfg["instances"] else "false"
        self_remove = "true" if self.cfg["self_remove"] else "false"
        show_progress = "true" if self.cfg["progress_bar"] else "false"
        extract_dll_line = 'ExtractResource("7z.dll", Path.Combine(workTemp, "7z.dll"));' if has_dll else ""

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

        cs_code = rf"""
using System;
using System.IO;
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
                    psi.WorkingDirectory = Path.GetTempPath();
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

            string targetDir;
            try
            {{
                string expanded = Environment.ExpandEnvironmentVariables(EXTRACT_TO.Trim().Trim('"').Replace("/", "\\"));
                if (expanded.Length == 2 && expanded[1] == ':')
                    expanded += "\\";
                targetDir = Path.GetFullPath(expanded);
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

            try
            {{
                Action<Action<int>> extractAction = delegate(Action<int> reportProgress)
                {{
                    try
                    {{
                        string sevenZExe = Path.Combine(workTemp, "7z.exe");
                        ExtractResource("7z.exe", sevenZExe);
                        {extract_dll_line}

                        // Native 7-Zip encryption can be read directly from the EXE overlay.
                        string archivePath = Application.ExecutablePath;

                        bool trackProgress = (reportProgress != null);
                        string outSwitch = targetDir.TrimEnd('\\');
                        if (outSwitch.Length == 2 && outSwitch[1] == ':')
                            outSwitch += "\\";
                        StringBuilder args = new StringBuilder();
                        args.Append(trackProgress ? "x -t7z -bsp1 " : "x -t7z ");
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
                                        if (readBuf[i] == '%')
                                        {{
                                            int d = i - 1;
                                            while (d >= 0 && readBuf[d] >= '0' && readBuf[d] <= '9') d--;
                                            int digits = i - 1 - d;
                                            if (digits >= 1 && digits <= 3)
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

                if (SHOW_PROGRESS && !HIDDEN_RUN)
                {{
                    ProgressBar pbControl;
                    Label lblControl;
                    using (Form progressForm = CreateProgressForm(out pbControl, out lblControl))
                    {{
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
                                        pbControl.Value = 100;
                                        progressForm.Close();
                                    }});
                            }}
                            catch {{ }}
                        }});
                        worker.IsBackground = true;
                        progressForm.Shown += delegate {{ worker.Start(); }};
                        progressForm.ShowDialog();
                    }}
                }}
                else
                {{
                    extractAction(null);
                }}

                if (extractError != null)
                    throw extractError;

                if (!EXTRACT_ONLY && !string.IsNullOrWhiteSpace(RUN_TARGET))
                {{
                    ExecuteRunFile(targetDir);
                }}
            }}
            catch (Exception ex)
            {{
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
                using (FileStream fs = File.Create(outPath))
                    s.CopyTo(fs);
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
            "/reference:System.dll",
            "/reference:System.Drawing.dll",
            "/reference:System.Windows.Forms.dll",
            f"/out:{work_exe}",
            f"/win32manifest:{manifest_path}",
            f"/resource:{seven_zip},7z.exe",
        ]
        if has_dll:
            csc_cmd.append(f"/resource:{seven_zip_dll},7z.dll")

        icon_bytes = self.cfg.get("icon_bytes") or get_default_sfx_icon_bytes()
        if icon_bytes:
            work_icon_path = os.path.join(work_dir, "icon.ico")
            with open(work_icon_path, "wb") as f_ico:
                f_ico.write(icon_bytes)
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
                    output.write(
                        b"\r\n" + _BW_SOURCE_START_MARKER + b"\r\n"
                        + cs_code.encode("utf-8")
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
                _remove_path_4_steps(staging_exe, False)
            if work_dir:
                _remove_path_4_steps(work_dir, True)
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


class SmartLineEdit(QLineEdit):
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
        if event.button() == Qt.MouseButton.LeftButton and not self.text().strip():
            self.open_selector()

    def contextMenuEvent(self, event):
        self.open_selector()

    def _format_run_file_selection(self, file_path: str) -> str:
        norm_file = expand_path(file_path, resolve_abs=True)
        if self.parent_win:
            src = expand_path(self.parent_win.inp_source.text(), resolve_abs=True)
            if os.path.isdir(src):
                rel = _relpath_if_within(norm_file, src)
                if rel and rel != ".":
                    return rel
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
            ):
                presets[menu.addAction(label)] = val
        elif self.mode == "output":
            act_folder = menu.addAction("1. Select Folder...")
            presets[menu.addAction("2. %UserProfile%\\Desktop")] = "%UserProfile%\\Desktop"
        elif self.mode == "run_file":
            act_file = menu.addAction("1. Select Executable / Script File...")

        menu.addSeparator()
        act_manual = menu.addAction(
            "Type Command / Path Manually" if self.mode == "run_file" else "Type Manually"
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
            if self.mode == "run_file" and self.parent_win:
                src = expand_path(self.parent_win.inp_source.text())
                start_dir = src if os.path.isdir(src) else (os.path.dirname(src) if os.path.isfile(src) else "")
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File", start_dir)
            if file_path:
                self._set_selected_path(
                    self._format_run_file_selection(file_path)
                    if self.mode == "run_file" else expand_path(file_path)
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
            elif self.mode == "run_file":
                self._set_selected_path(self._format_run_file_selection(dropped_path))
            else:
                self._set_selected_path(dropped_path)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


# ==============================================================================
# 4. MAIN APPLICATION WINDOW (ORGANIZED BY GUI SECTIONS)
# ==============================================================================
class ByteWrapperWindow(QWidget):
    # --------------------------------------------------------------------------
    # 4.1. GUI INITIALIZATION, STYLES & WINDOW CONTROLS
    # --------------------------------------------------------------------------
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Byte Wrapper")
        self.setFixedSize(380, 600)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Window)
        self.setAcceptDrops(True)

        self.current_icon_bytes: bytes = b""
        self.current_icon_source: str = ""

        cleanup_temp_files_now()

        dpr = max(1.0, self.devicePixelRatioF())
        default_img = get_default_parcel_image()
        self.default_gui_icon = QIcon(pil_to_qpixmap(default_img, 256, dpr))
        self.default_btn_icon = QIcon(pil_to_qpixmap(default_img, 24, dpr))
        self.setWindowIcon(self.default_gui_icon)

        self._user_edited_name = False
        self._user_dont_replace = False
        self._tracked_source_path = ""
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

        self.init_ui()
        self.apply_styles()

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

        # --- GROUP 1: PATH INPUT FIELDS ---
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

        self.inp_name = QLineEdit()
        self.inp_name.setPlaceholderText("Name...")
        self.inp_name.setFixedHeight(34)
        self.inp_name.setValidator(win_filename_validator)
        self.inp_name.textEdited.connect(self.on_name_manually_edited)
        self.inp_name.textChanged.connect(self._sync_dont_replace_state)
        nd_layout.addWidget(self.inp_name, stretch=4)

        self.inp_desc = QLineEdit()
        self.inp_desc.setPlaceholderText("Description...")
        self.inp_desc.setFixedHeight(34)
        self.inp_desc.setValidator(win_filename_validator)
        nd_layout.addWidget(self.inp_desc, stretch=4)

        self.inp_version = QLineEdit()
        self.inp_version.setObjectName("VersionInput")
        self.inp_version.setPlaceholderText("Ver...")
        self.inp_version.setToolTip("Package file version (e.g. 1.0.0.0)")
        self.inp_version.setFixedSize(64, 34)
        ver_part = r"(?:6553[0-4]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[0-9]{1,4})"
        ver_validator = QRegularExpressionValidator(
            QRegularExpression(rf"^(?:{ver_part}(?:\.{ver_part}){{0,3}})?$"), self.inp_version
        )
        self.inp_version.setValidator(ver_validator)
        nd_layout.addWidget(self.inp_version)

        main_layout.addLayout(nd_layout)

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

        fields = (
            self.inp_source, self.inp_extract, self.inp_run, self.inp_output,
            self.inp_name, self.inp_desc, self.inp_version, self.inp_password
        )
        for field in fields:
            field.textChanged.connect(self.reset_start_status)
        for option in all_checks:
            option.toggled.connect(self.reset_start_status)
        self._build_controls = (
            self.logo_label, self.btn_icon, self.btn_export, self.btn_import,
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
    def _sync_dont_replace_state(
        self, *_args, norm_source: str = "", norm_output: str = "", resolved: bool = False
    ):
        if self._updating_ui:
            return
        conflict = _single_file_conflicts_with_output(
            norm_source if resolved else self.inp_source.text(),
            norm_output if resolved else self.inp_output.text(),
            self.inp_name.text(),
            resolved=resolved,
        )
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
        self, sync_replace: bool = True, norm_source: str = "", norm_output: str = "", resolved: bool = False
    ) -> bool:
        if self._updating_ui:
            return True
        src = norm_source if resolved else expand_path(self.inp_source.text(), resolve_abs=True)
        out = norm_output if resolved else expand_path(self.inp_output.text(), resolve_abs=True)
        if _output_conflicts_with_source(src, out, resolved=True):
            self._updating_ui = True
            try:
                self.inp_output.clear()
            finally:
                self._updating_ui = False
            self.inp_output.setToolTip("Output cannot be the source folder or one of its subfolders.")
            self._sync_dont_replace_state(norm_source=src, norm_output="", resolved=True)
            return False
        self.inp_output.setToolTip("")
        if sync_replace:
            self._sync_dont_replace_state(norm_source=src, norm_output=out, resolved=True)
        return True

    def _auto_fill_name_from_source_dir(self):
        if not self._user_edited_name and not self.inp_name.text().strip():
            target = expand_path(self.inp_source.text())
            if target and os.path.isdir(target):
                folder_stem = _derive_auto_name_from_path(target, strip_ext=False)
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
        self._user_edited_name = False
        self._last_run_cand = ""

        self._updating_ui = True
        try:
            if expanded and os.path.isfile(expanded):
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
                    if (self.chk_extract_only.isChecked() and expanded and os.path.isdir(expanded))
                    else ""
                )
                if self.inp_name.text() != folder_stem:
                    self.inp_name.setText(folder_stem)
                self.reset_icon_to_default()
        finally:
            self._updating_ui = False
            self.validate_output_path(
                norm_source=expanded,
                norm_output=expand_path(self.inp_output.text(), resolve_abs=True),
                resolved=True,
            )

    def on_run_file_changed(self, text: str):
        if self._updating_ui or self._user_edited_name:
            return
        raw = text.strip()
        if not raw:
            self._last_run_cand = ""
            if self.inp_name.text():
                self._updating_ui = True
                self.inp_name.clear()
                self._updating_ui = False
                self._sync_dont_replace_state()
            return

        candidate, _ = _split_command_and_args(raw)
        if candidate == self._last_run_cand:
            return
        self._last_run_cand = candidate

        stem_clean = _derive_auto_name_from_path(candidate, strip_ext=True)
        if stem_clean and self.inp_name.text() != stem_clean:
            self._updating_ui = True
            self.inp_name.setText(stem_clean)
            self._updating_ui = False
            self._sync_dont_replace_state()

    # --------------------------------------------------------------------------
    # 4.4. GROUP 2 HANDLERS: ICON, NAME, DESCRIPTION, VERSION
    # --------------------------------------------------------------------------
    def _set_button_icon_pil(self, pil_img: Image.Image | None):
        if pil_img is None:
            self.btn_icon.setIcon(self.default_btn_icon)
        else:
            dpr = max(1.0, self.devicePixelRatioF())
            self.btn_icon.setIcon(QIcon(pil_to_qpixmap(pil_img, 24, dpr)))

    def reset_icon_to_default(self, _pos=None):
        had_custom = bool(self.current_icon_source or self.current_icon_bytes)
        self.current_icon_source = ""
        self.current_icon_bytes = b""
        if had_custom:
            self.btn_icon.setIcon(self.default_btn_icon)
        self.btn_icon.setToolTip(
            'Default Byte Wrapper icon restored. Left-click or drop file to select another.'
            if had_custom else
            'Left-click or drop file: set icon. Right-click: restore default icon.'
        )
        self.reset_start_status()

    def open_icon_menu(self):
        menu = QMenu(self)
        act_auto = menu.addAction("1. Get Automatically from Run File")
        act_select = menu.addAction("2. Select Icon...")
        act_imageres = menu.addAction("3. Select from imageres.dll...")
        act_shell32 = menu.addAction("4. Select from shell32.dll...")

        action = menu.exec(self.btn_icon.mapToGlobal(QPoint(0, self.btn_icon.height())))
        if action == act_auto:
            self.set_icon_from_run_file()
        elif action == act_select:
            self.select_icon_from_dialog()
        elif action == act_imageres:
            self.select_icon_from_system_dll("imageres.dll")
        elif action == act_shell32:
            self.select_icon_from_system_dll("shell32.dll")

    def apply_custom_icon_file(self, file_path: str, icon_idx: int | None = None) -> bool:
        resolved_path, resolved_idx = _split_icon_source(file_path, icon_idx)
        if not resolved_path:
            self.btn_icon.setToolTip("Could not extract or convert the selected icon.")
            return False
        ico_bytes, pil_img = extract_icon_from_file(resolved_path, resolved_idx)
        if not ico_bytes or pil_img is None:
            self.btn_icon.setToolTip("Could not extract or convert the selected icon.")
            return False
        self.current_icon_source = f"{resolved_path},{resolved_idx}" if resolved_idx is not None else resolved_path
        self.current_icon_bytes = ico_bytes
        self._set_button_icon_pil(pil_img)
        label = (
            f"{os.path.basename(resolved_path)} (#{resolved_idx})"
            if resolved_idx is not None else os.path.basename(resolved_path)
        )
        self.btn_icon.setToolTip(f"Icon loaded from: {label}")
        self.reset_start_status()
        return True

    def select_icon_from_system_dll(self, dll_name: str):
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        dll_path = os.path.join(sys32, dll_name)
        if not os.path.isfile(dll_path):
            return
        buf = ctypes.create_unicode_buffer(dll_path, 260)
        icon_idx = ctypes.c_int(0)
        if _SHELL32.PickIconDlg(int(self.winId()), buf, 260, ctypes.byref(icon_idx)):
            self.apply_custom_icon_file(expand_path(buf.value), icon_idx.value)

    def set_icon_from_run_file(self):
        cmd_part, _ = _split_command_and_args(self.inp_run.text())
        target_file = _locate_run_file_in_source(self.inp_source.text(), cmd_part)
        if not target_file:
            self.btn_icon.setToolTip("Could not locate an icon from Run File or Source Folder.")
            return
        self.apply_custom_icon_file(target_file)

    def select_icon_from_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Icon or Application",
            "",
            "Icon & Executable Files (*.ico *.png *.jpeg *.jpg *.jxl *.exe)"
        )
        if file_path:
            self.apply_custom_icon_file(expand_path(file_path))

    def on_name_manually_edited(self, text: str):
        self._user_edited_name = bool(text.strip())

    # --------------------------------------------------------------------------
    # 4.5. GROUP 3 HANDLERS: OPTIONS CHECKBOXES
    # --------------------------------------------------------------------------
    def on_dont_replace_toggled(self, checked: bool):
        if self._updating_ui:
            return
        if _single_file_conflicts_with_output(
            self.inp_source.text(), self.inp_output.text(), self.inp_name.text()
        ):
            if not checked:
                self._updating_ui = True
                try:
                    self.chk_dont_replace.setChecked(True)
                finally:
                    self._updating_ui = False
            return
        self._user_dont_replace = checked

    def on_extract_only_toggled(self, checked: bool):
        if self._updating_ui:
            return
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
        pw = self.inp_password.text()
        if not pw.strip():
            pw = ""
        cfg = {
            "source": self.inp_source.text(),
            "extract_to": self.inp_extract.text(),
            "run_file": self.inp_run.text(),
            "output": self.inp_output.text(),
            "name": self.inp_name.text(),
            "description": self.inp_desc.text(),
            "version": self.inp_version.text(),
            "icon_source": self.current_icon_source,
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
        return cfg

    def export_config(self):
        export_data = self.collect_config(include_icon_bytes=False)
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
                _remove_path_4_steps(tmp_path, False)
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

            ver_val = str_vals["version"].strip()
            if _parse_pe_version(ver_val) is None:
                raise ValueError("Version must be 1 to 4 numbers (0-65534) separated by dots.")

            name_val = str_vals["name"]
            if name_val and _validate_package_name(name_val) is None:
                raise ValueError("Package name contains invalid characters or is a reserved Windows file name.")

            desc_val = str_vals["description"]
            if _INVALID_FILENAME_CHARS_RE.search(desc_val):
                raise ValueError("Description contains invalid characters.")

            pw_val = decrypt_password_from_import(str_vals["password"])
        except Exception as e:
            err_msg = f"Failed to import configuration: {e}"
            self.btn_import.setToolTip(err_msg)
            self._fail_start(err_msg)
            return

        self._updating_ui = True
        expanded_src = ""
        try:
            run_val = str_vals["run_file"]
            src_val = str_vals["source"]
            extract_only = bool_vals["extract_only"]
            self._user_edited_name = bool(name_val.strip())
            expanded_src = expand_path(src_val, resolve_abs=True) if src_val.strip() else ""
            self._tracked_source_path = os.path.normcase(expanded_src) if expanded_src else ""

            cand, _ = _split_command_and_args(run_val)
            self._last_run_cand = cand
            if not name_val.strip():
                if cand:
                    name_val = _derive_auto_name_from_path(cand, strip_ext=True)
                elif expanded_src and os.path.isfile(expanded_src):
                    name_val = _derive_auto_name_from_path(expanded_src, strip_ext=True)
                elif extract_only and expanded_src and os.path.isdir(expanded_src):
                    name_val = _derive_auto_name_from_path(expanded_src, strip_ext=False)

            self.inp_source.setText(src_val)
            self.inp_extract.setText(str_vals["extract_to"])
            self.inp_name.setText(name_val)
            self.inp_run.setText(run_val)
            self.inp_output.setText(str_vals["output"])
            self.inp_desc.setText(desc_val)
            self.inp_version.setText(ver_val)

            hidden_run = False if extract_only else bool_vals["hidden_run"]
            dont_replace_val = bool_vals["dont_replace"]
            self._user_dont_replace = dont_replace_val

            self.chk_admin.setChecked(bool_vals["run_as_admin"])
            self.chk_hidden.setChecked(hidden_run)
            self.chk_dont_replace.setChecked(dont_replace_val)
            self.chk_extract_only.setChecked(extract_only)
            self.chk_self_remove.setChecked(bool_vals["self_remove"])
            self.chk_progress_bar.setChecked(bool_vals["progress_bar"])
            self.chk_compress.setChecked(bool_vals["compress"])
            self.chk_crypto.setChecked(bool_vals["crypto"])
            self.chk_instances.setChecked(bool_vals["instances"])
            self.inp_run.setEnabled(not extract_only)
            self._refresh_hidden_availability()

            self.inp_password.setText(pw_val)

            raw_icon_src = str_vals["icon_source"].strip()
            if not (raw_icon_src and self.apply_custom_icon_file(raw_icon_src)):
                self.reset_icon_to_default()

            self.btn_import.setToolTip("")
        finally:
            self._updating_ui = False
            self.validate_output_path(
                norm_source=expanded_src,
                norm_output=expand_path(self.inp_output.text(), resolve_abs=True),
                resolved=True,
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

        raw_source = self.inp_source.text().strip()
        raw_extract = self.inp_extract.text().strip()
        raw_run = self.inp_run.text().strip()
        raw_output = self.inp_output.text().strip()

        if not (raw_source or raw_extract or raw_run or raw_output):
            return

        self._status_reset_timer.stop()
        self._status_dirty = False

        norm_source = expand_path(raw_source, resolve_abs=True)
        if not norm_source or _has_invalid_path_chars(norm_source):
            self._fail_start("Source folder or file path is invalid.")
            return

        if not os.path.exists(norm_source):
            self._fail_start("Source folder or file does not exist.")
            return

        extract_clean = raw_extract.strip('"').strip("'").strip()
        if _has_invalid_path_chars(extract_clean):
            self._fail_start("Extract To cannot be empty or contain invalid characters.")
            return

        extract_only = self.chk_extract_only.isChecked()
        cmd_part, run_args = ("", "") if extract_only else _split_command_and_args(raw_run)
        if not extract_only and _has_invalid_path_chars(cmd_part):
            self._fail_start("Run File cannot be empty or contain invalid path characters.")
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
            sync_replace=False, norm_source=norm_source, norm_output=norm_output, resolved=True
        ):
            self._fail_start("Output cannot be the source folder or one of its subfolders.")
            return

        base_name = _validate_package_name(self.inp_name.text())
        if base_name is None:
            self._fail_start("Package name contains invalid characters or is a reserved Windows file name.")
            return

        raw_desc = self.inp_desc.text().strip()
        if _INVALID_FILENAME_CHARS_RE.search(raw_desc):
            self._fail_start("Description contains invalid characters.")
            return

        parsed_ver = _parse_pe_version(self.inp_version.text())
        if parsed_ver is None:
            self._fail_start("Version must be 1 to 4 numbers (0-65534) separated by dots.")
            return

        seven_zip = SFXBuilderWorker.find_7zip()
        if not seven_zip:
            self._fail_start("7-Zip (7z.exe) was not found! Please make sure 7-Zip is installed.")
            return

        csc_path = SFXBuilderWorker.find_csc()
        if not csc_path:
            self._fail_start("Windows .NET C# compiler (csc.exe) was not found!")
            return

        cfg = self.collect_config()
        cfg["source"] = norm_source
        cfg["output"] = norm_output
        cfg["extract_to"] = extract_clean
        cfg["description"] = raw_desc
        cfg["cmd_part"] = cmd_part
        cfg["run_args"] = run_args
        cfg["base_name"] = base_name
        cfg["parsed_version"] = parsed_ver
        cfg["seven_zip"] = seven_zip
        cfg["csc_path"] = csc_path

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
    app = QApplication(sys.argv)
    win = ByteWrapperWindow()
    win.show()
    sys.exit(app.exec())