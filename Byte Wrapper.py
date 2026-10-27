import os
import re
import sys
import json
import struct
import base64
import hashlib
import shutil
import ctypes
import subprocess
import tempfile
import time
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


from PyQt6.QtCore import Qt, QPoint, QThread, pyqtSignal, QSize, QTimer
from PyQt6.QtGui import (
    QIcon, QPixmap, QDragEnterEvent, QDropEvent
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
# HIGH-DEFINITION ICON UTILITIES
# ==========================================
def save_crisp_multi_ico(master_img: Image.Image, out_ico_path: str,
                         sizes=(256, 128, 64, 48, 32, 24, 16)) -> bool:
    """Build a multi-resolution Windows ICO with LANCZOS resampling per layer.

    Unlike Pillow's default single-image ICO writer, this resamples every layer
    directly from the high-resolution master image, applies subtle edge sharpening
    for small icon sizes, and writes a PNG frame for 256x256 plus 32-bit BGRA DIB
    frames for smaller sizes (ordered largest-first).
    """
    try:
        src = master_img.convert("RGBA")
        # Ensure square canvas while preserving aspect ratio
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
                    40,                        # biSize
                    sz,                        # biWidth
                    sz * 2,                    # biHeight (XOR + AND)
                    1,                         # biPlanes
                    32,                        # biBitCount
                    0,                         # biCompression (BI_RGB)
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
    icon_path = os.path.join(tempfile.gettempdir(), "byte_wrapper_vector_box_v4.ico")
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
                for _, _, _, offset, size, chunk in candidates:
                    if chunk.startswith(b"\x89PNG\r\n\x1a\n"):
                        with Image.open(io.BytesIO(chunk)) as png_img:
                            return png_img.convert("RGBA")
                    # Reconstruct a single-entry ICO in memory so Pillow decodes this exact layer
                    single_dir = bytearray(data[6:22])
                    for _, _, idx, _, _, _ in candidates:
                        pos = 6 + idx * 16
                        single_dir = bytearray(data[pos:pos + 16])
                        break
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

    kernel32 = ctypes.windll.kernel32
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
            if isinstance(res_id, int):
                name_ptr = ctypes.c_void_p(res_id)
            else:
                name_ptr = ctypes.cast(ctypes.c_wchar_p(res_id), ctypes.c_void_p)
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
            # Update dwBytesInRes with exact chunk size and append 4-byte file offset
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

    # Query Windows Shell file association DefaultIcon
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

    # 1. Try direct lossless PE resource extraction (plus Windows 10/11 .mun resource store)
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
                # Verify and normalize if needed
                best_pil = load_best_pil_from_ico(out_ico_path)
                if best_pil is not None and best_pil.width >= 48:
                    return True
            except OSError:
                pass

    # 2. Fallback: Use PrivateExtractIconsW with a 32-bit RGBA DIBSection
    try:
        import win32ui
        import win32gui
        import win32con

        hicon = 0
        for candidate in candidates_to_try:
            phicon = (ctypes.c_void_p * 1)()
            piconid = (ctypes.c_uint * 1)()
            count = ctypes.windll.user32.PrivateExtractIconsW(
                ctypes.c_wchar_p(candidate), icon_idx, 256, 256,
                phicon, piconid, 1, 0
            )
            if count > 0 and phicon[0]:
                hicon = phicon[0]
                break

        if not hicon:
            buf = ctypes.create_unicode_buffer(file_path, 260)
            pi_icon = ctypes.c_uint16(0)
            hicon = ctypes.windll.shell32.ExtractAssociatedIconW(0, buf, ctypes.byref(pi_icon))

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
            ctypes.windll.user32.DestroyIcon(hicon)
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
                    norm_start = os.path.normpath(start_dir) if start_dir else ""
                    if norm_start and (
                        norm_file.lower() == norm_start.lower()
                        or norm_file.lower().startswith(norm_start.lower() + os.sep)
                    ):
                        rel_path = os.path.relpath(norm_file, norm_start)
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
                    dropped_path = os.path.normpath(local_path)
                    if self.mode == "source" and self.parent_win is not None:
                        self.parent_win.on_source_dropped(dropped_path)
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


def _looks_like_self_elevating_script(path: str) -> bool:
    """Recognize common script self-elevation patterns without executing the script.

    Used to request normal Windows UAC consent before Hidden Run.
    The detection is intentionally conservative.
    """
    try:
        if not path or not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext not in (".bat", ".cmd", ".ps1"):
            return False
        with open(path, "rb") as f:
            content = f.read(512 * 1024).decode("utf-8-sig", errors="replace")
        # Exclude ordinary line comments; preserve the actual commands.
        lines = [line for line in content.splitlines()
                 if not re.match(r"^\s*(?:rem\s|::|#)", line, re.IGNORECASE)]
        active = "\n".join(lines)
        if ext == ".ps1":
            return bool(re.search(r"(?i)\bstart-process\b[^\r\n]*\s-verb\s+['\"]?runas\b", active))
        # WindowsUpdateTools.cmd: `fltmc || ... start ...` invokes a second
        # console through a temporary .Admin file association without admin.
        if re.search(r"(?im)^.*\b(?:fltmc|net\s+session)\b[^\r\n]*\|\|[^\r\n]*\bstart\b", active):
            return True
        # Common BAT elevation via PowerShell and ShellExecute RunAs.
        return bool(re.search(r"(?i)\bstart-process\b[^\r\n]*-verb\s+['\"]?runas\b", active))
    except (OSError, UnicodeError):
        return False


def _remove_build_directory_safely(path: str) -> bool:
    """Retry transient Windows sharing violations without atexit cleanup errors.

    Windows AV/indexers may briefly hold payload.dat after csc.exe exits.
    Failure to delete a temporary directory must never invalidate a built EXE.
    """
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
            fs_stamp = now_dt.strftime("%d.%m.%Y %H.%M.%S")
            target_path = os.path.join(out_dir, f"{name}_{fs_stamp}.exe")

        return target_path

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

    def build_7z_archive(self, seven_zip: str, source_path: str, archive_path: str) -> subprocess.CompletedProcess:
        cmd = [seven_zip, "a"]

        if self.cfg["compress"]:
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
            cmd.extend([f"-p{internal_pw}", "-mhe=on"])

        cmd.extend(["-y", archive_path])

        if os.path.isdir(source_path):
            cmd.append(os.path.join(source_path, "*"))
        else:
            cmd.append(source_path)

        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        return subprocess.run(cmd, capture_output=True, text=True, creationflags=creation_flags)

    def prepare_payload(self, raw_7z_path: str, out_dat_path: str) -> tuple[str, bool]:
        """
        When Crypto is enabled, scrambles the binary payload in chunks
        so the encrypted package is not directly readable by 7-Zip.
        When Crypto is disabled, reuses raw_7z_path directly so 7-Zip can open it.
        """
        if not self.cfg["crypto"]:
            return raw_7z_path, False

        key_bytes = b"byte_wrapper_secret_key_2026"
        key_len = len(key_bytes)
        chunk_size = 1024 * 1024  # 1 MB chunks
        offset = 0

        with open(raw_7z_path, "rb") as fin, open(out_dat_path, "wb") as fout:
            while True:
                buf = bytearray(fin.read(chunk_size))
                if not buf:
                    break
                for i in range(len(buf)):
                    global_idx = offset + i
                    buf[i] ^= key_bytes[global_idx % key_len] ^ ((global_idx & 0xFF) ^ 0xA5)
                fout.write(buf)
                offset += len(buf)

        return out_dat_path, True

    def compile_csharp_sfx(self, csc_path: str, work_dir: str, payload_dat: str, scrambled: bool, seven_zip: str, target_exe: str) -> tuple[bool, str]:
        shutil.copy2(seven_zip, os.path.join(work_dir, "7z.exe"))
        seven_zip_dll = os.path.join(os.path.dirname(seven_zip), "7z.dll")
        has_dll = os.path.isfile(seven_zip_dll)
        if has_dll:
            shutil.copy2(seven_zip_dll, os.path.join(work_dir, "7z.dll"))

        src_norm = os.path.normpath(os.path.expandvars(self.cfg["source"].strip()))
        source_folder_name = os.path.basename(src_norm) if os.path.isdir(src_norm) else ""

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

        extract_to_str = cs_escape(self.cfg["extract_to"].strip())
        run_file_str = cs_escape(self.cfg["run_file"].strip())
        source_folder_name_str = cs_escape(source_folder_name)

        internal_7z_pw = cs_escape(self.get_internal_7z_password())
        ask_user_pw = "true" if (self.cfg["use_password"] and bool(self.cfg["password"])) else "false"
        expected_user_pw = cs_escape(self.cfg["password"])

        is_scrambled = "true" if scrambled else "false"
        # A transparent package stores its 7z archive ONLY as the final EXE
        # overlay. Previously it was also embedded in the .NET resources,
        # pushing the outer 7z signature past archive scanners' search limit.
        overlay_archive_size = 0 if scrambled else os.path.getsize(payload_dat)
        hidden_run = "true" if self.cfg["hidden_run"] else "false"
        # Only scripts that deliberately relaunch themselves for elevation
        # need the wrapper to obtain normal UAC approval first.
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

        cs_code = rf"""
using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Reflection;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
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
        private static readonly long OVERLAY_ARCHIVE_SIZE = {overlay_archive_size}L;
        private static readonly bool HIDDEN_RUN = {hidden_run};
        private static readonly bool HIDDEN_SCRIPT_NEEDS_ADMIN = {hidden_script_needs_admin};
        private static readonly bool EXTRACT_ONLY = {extract_only};
        private static readonly bool INSTANCES = {instances};
        private static readonly bool SELF_REMOVE = {self_remove};
        private static readonly bool SHOW_PROGRESS = {show_progress};

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

        [STAThread]
        static void Main()
        {{
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // An unelevated self-elevating CMD would create a second, visible
            // console outside the hidden launcher. Ask Windows for UAC consent
            // BEFORE the CMD runs. Existing administrative launches are unchanged.
            if (HIDDEN_RUN && HIDDEN_SCRIPT_NEEDS_ADMIN && !IsRunningAsAdministrator())
            {{
                RelaunchPackageElevatedHidden();
                return;
            }}

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
                : Environment.ExpandEnvironmentVariables(EXTRACT_TO.Replace("/", "\\"));

            if (!string.IsNullOrEmpty(SOURCE_FOLDER_NAME) && !string.IsNullOrEmpty(RUN_FILE))
            {{
                string expandedRun = Environment.ExpandEnvironmentVariables(RUN_FILE.Replace("/", "\\"));
                string expectedSub = Path.Combine(targetDir, SOURCE_FOLDER_NAME);
                if (expandedRun.StartsWith(expectedSub + "\\", StringComparison.OrdinalIgnoreCase) &&
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
                if (!HIDDEN_RUN)
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
                if (IS_SCRAMBLED)
                    ExtractResource("payload.dat", archive7z, true);
                else
                    ExtractOverlayArchive(archive7z);

                Application.DoEvents();

                StringBuilder args = new StringBuilder();
                args.Append("x \"" + archive7z + "\" ");
                args.Append("-o\"" + targetDir + "\" ");
                if (!string.IsNullOrEmpty(INTERNAL_7Z_PW))
                {{
                    string safePw = INTERNAL_7Z_PW.Replace("\"", "\\\"");
                    args.Append("-p\"" + safePw + "\" ");
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
                    if (p == null)
                        throw new InvalidOperationException("7-Zip extractor could not start.");
                    while (!p.WaitForExit(50))
                    {{
                        Application.DoEvents();
                    }}
                    if (p.ExitCode != 0)
                        throw new InvalidDataException("7-Zip extraction failed with exit code " + p.ExitCode);
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
            catch (Exception ex)
            {{
                if (!HIDDEN_RUN)
                    MessageBox.Show("Package processing failed: " + ex.Message,
                        "Byte Wrapper", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }}
            finally
            {{
                if (progressForm != null)
                {{
                    progressForm.Close();
                    progressForm.Dispose();
                }}
                try {{ Directory.Delete(workTemp, true); }} catch {{ }}
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

        private static void RelaunchPackageElevatedHidden()
        {{
            try
            {{
                // The user must approve Windows' regular UAC prompt. No bypass.
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Application.ExecutablePath;
                psi.WorkingDirectory = Path.GetDirectoryName(Application.ExecutablePath);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                using (Process process = Process.Start(psi))
                {{
                    // Dispose the launcher handle; the elevated package continues independently.
                }}
            }}
            catch (Win32Exception)
            {{
                // UAC cancellation or launch failure: do not start visibly as a fallback.
            }}
            catch (Exception)
            {{
                // No log file is created.
            }}
        }}

        private static void ExecuteRunFile(string targetDir)
        {{
            string rawCmd = Environment.ExpandEnvironmentVariables(RUN_FILE.Trim().Replace("/", "\\"));
            string resolvedFile = "";
            string arguments = "";

            if (File.Exists(Path.Combine(targetDir, rawCmd)))
            {{
                resolvedFile = Path.GetFullPath(Path.Combine(targetDir, rawCmd));
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
                    string[] knownExtensions = new string[] {{ ".bat", ".cmd", ".ps1", ".exe", ".msi", ".reg" }};
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

                if (File.Exists(Path.Combine(targetDir, candidatePath)))
                {{
                    resolvedFile = Path.GetFullPath(Path.Combine(targetDir, candidatePath));
                }}
                else if (File.Exists(candidatePath))
                {{
                    resolvedFile = Path.GetFullPath(candidatePath);
                }}
                else
                {{
                    string fileNameOnly = Path.GetFileName(candidatePath);
                    if (!string.IsNullOrEmpty(fileNameOnly))
                    {{
                        string directMatch = Path.Combine(targetDir, fileNameOnly);
                        if (File.Exists(directMatch))
                        {{
                            resolvedFile = Path.GetFullPath(directMatch);
                        }}
                        else
                        {{
                            try
                            {{
                                string[] found = Directory.GetFiles(targetDir, fileNameOnly, SearchOption.AllDirectories);
                                if (found.Length > 0)
                                    resolvedFile = Path.GetFullPath(found[0]);
                            }}
                            catch {{ }}
                        }}
                    }}
                }}
            }}

            // File.Exists can accept relative paths, but WorkingDirectory cannot be empty.
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

            if (ext == ".reg" || rawCmd.IndexOf("regedit", StringComparison.OrdinalIgnoreCase) >= 0)
            {{
                fileNameToStart = "regedit.exe";
                if (!string.IsNullOrEmpty(resolvedFile))
                {{
                    argsToStart = (HIDDEN_RUN ? "/s " : "") + "\"" + resolvedFile + "\"" +
                        (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                }}
                else
                {{
                    argsToStart = rawCmd;
                    if (HIDDEN_RUN && argsToStart.IndexOf("/s", StringComparison.OrdinalIgnoreCase) < 0)
                        argsToStart = "/s " + argsToStart;
                }}
                RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
                return;
            }}

            if (ext == ".ps1")
            {{
                fileNameToStart = "powershell.exe";
                argsToStart = "-NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                    (HIDDEN_RUN ? "-WindowStyle Hidden " : "") +
                    "-File \"" + resolvedFile + "\"" +
                    (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
                return;
            }}

            if (ext == ".bat" || ext == ".cmd")
            {{
                fileNameToStart = "cmd.exe";
                argsToStart = "/D /S /C \"\"" + resolvedFile + "\"" +
                    (string.IsNullOrEmpty(arguments) ? "" : " " + arguments) + "\"";
                RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
                return;
            }}

            if (ext == ".msi")
            {{
                fileNameToStart = "msiexec.exe";
                argsToStart = "/i \"" + resolvedFile + "\"" +
                    (HIDDEN_RUN ? " /qn /norestart" : "") +
                    (string.IsNullOrEmpty(arguments) ? "" : " " + arguments);
                RunNativeProcess(fileNameToStart, argsToStart, workDir, HIDDEN_RUN);
                return;
            }}

            if (!string.IsNullOrEmpty(resolvedFile) && File.Exists(resolvedFile))
            {{
                RunNativeProcess(resolvedFile, arguments, workDir, HIDDEN_RUN);
                return;
            }}

            RunNativeProcess("cmd.exe", "/D /S /C \"cd /d \"" + workDir + "\" && " + rawCmd + "\"", workDir, HIDDEN_RUN);
        }}

        private static bool TryRunHiddenNative(string fileName, string arguments, string workDir)
        {{
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            startup.dwFlags = STARTF_USESHOWWINDOW;
            startup.wShowWindow = SW_HIDE;

            string command = "\"" + fileName + "\"" +
                (string.IsNullOrWhiteSpace(arguments) ? "" : " " + arguments);
            StringBuilder commandBuffer = new StringBuilder(command);
            PROCESS_INFORMATION processInfo;
            bool started = CreateProcessW(null, commandBuffer, IntPtr.Zero, IntPtr.Zero,
                false, CREATE_NO_WINDOW, IntPtr.Zero, workDir, ref startup, out processInfo);
            if (!started)
                return false;

            // CreateProcessW succeeded: the child now runs independently.
            // Close ONLY our process/thread handles. Closing these handles does
            // not terminate the launched program or its child processes.
            if (processInfo.hThread != IntPtr.Zero)
                CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero)
                CloseHandle(processInfo.hProcess);
            return true;
        }}

        private static void RunNativeProcess(string fileName, string arguments, string workDir, bool hidden)
        {{
            try
            {{
                // Apply Win32 STARTUPINFO.SW_HIDE and CREATE_NO_WINDOW together.
                // ProcessStartInfo alone cannot provide both settings on all
                // .NET Framework launch paths. This controls the initial
                // process window; an app can still open its own windows.
                if (hidden && TryRunHiddenNative(fileName, arguments, workDir))
                    return;

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = fileName;
                psi.Arguments = arguments;
                psi.WorkingDirectory = workDir;
                // Shell fallback supports manifests requiring elevation.
                psi.UseShellExecute = hidden;
                psi.CreateNoWindow = false;
                psi.WindowStyle = hidden ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal;

                using (Process p = Process.Start(psi))
                {{
                    // Dispose the launcher handle without waiting for the child.
                    // The extracted Run File keeps running after this stub exits.
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
                            // UAC launch was accepted: the elevated child is independent.
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
        }}

        private static void SelfDeleteExe()
        {{
            try
            {{
                string exePath = Application.ExecutablePath;
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/D /C for /L %i in (1,1,15) do @(if exist \"" + exePath + "\" (del /f /q \"" + exePath + "\" >nul 2>&1 & if exist \"" + exePath + "\" ping 127.0.0.1 -n 2 >nul))";
                psi.WorkingDirectory = Path.GetTempPath();
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }}
            catch {{ }}
        }}

        private static void ExtractOverlayArchive(string outPath)
        {{
            if (OVERLAY_ARCHIVE_SIZE < 32L)
                throw new InvalidDataException("No readable 7z overlay is configured.");

            using (FileStream source = new FileStream(Application.ExecutablePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {{
                if (source.Length < OVERLAY_ARCHIVE_SIZE)
                    throw new InvalidDataException("The 7z overlay is missing or incomplete.");

                long offset = source.Length - OVERLAY_ARCHIVE_SIZE;
                source.Seek(offset, SeekOrigin.Begin);
                byte[] magic = new byte[] {{ 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }};
                for (int i = 0; i < magic.Length; i++)
                    if (source.ReadByte() != magic[i])
                        throw new InvalidDataException("The 7z overlay signature is invalid.");
                source.Seek(offset, SeekOrigin.Begin);

                using (FileStream dest = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {{
                    long remaining = OVERLAY_ARCHIVE_SIZE;
                    byte[] buffer = new byte[65536];
                    while (remaining > 0L)
                    {{
                        int want = (int)Math.Min((long)buffer.Length, remaining);
                        int read = source.Read(buffer, 0, want);
                        if (read <= 0)
                            throw new EndOfStreamException("The 7z overlay ended early.");
                        dest.Write(buffer, 0, read);
                        remaining -= read;
                    }}
                }}
            }}
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

                byte[] key = Encoding.ASCII.GetBytes("byte_wrapper_secret_key_2026");
                int klen = key.Length;
                byte[] buffer = new byte[65536];
                long totalOffset = 0;

                using (FileStream fs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {{
                    int read;
                    while ((read = s.Read(buffer, 0, buffer.Length)) > 0)
                    {{
                        if (unscramble)
                        {{
                            for (int i = 0; i < read; i++)
                            {{
                                long idx = totalOffset + i;
                                buffer[i] = (byte)(buffer[i] ^ key[idx % klen] ^ ((idx & 0xFF) ^ 0xA5));
                            }}
                        }}
                        fs.Write(buffer, 0, read);
                        totalOffset += read;
                    }}
                }}
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
            f'/resource:{os.path.join(work_dir, "7z.exe")},7z.exe',
        ]
        if has_dll:
            csc_cmd.append(f'/resource:{os.path.join(work_dir, "7z.dll")},7z.dll')
        if scrambled:
            csc_cmd.append(f'/resource:{payload_dat},payload.dat')

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

        # Retain the generated C# for the header-logo SFX code viewer.
        # The source preview MUST precede the overlay archive: the final
        # OVERLAY_ARCHIVE_SIZE bytes are the raw, byte-identical .7z payload.
        with open(target_exe, 'ab') as output:
            output.write(b'\r\n;!@ByteWrapperSource@UTF-8!\r\n')
            output.write(cs_code.encode('utf-8'))
            output.write(b'\r\n;!@ByteWrapperSourceEnd@!\r\n')

        if not scrambled:
            # In transparent mode the archive is appended exactly once. The
            # stub streams it back from the EXE's final bytes when launched.
            with open(payload_dat, "rb") as archive, open(target_exe, "ab") as output:
                shutil.copyfileobj(archive, output)

        return True, target_exe

    def run(self):
        work_dir = None
        success = False
        message = ""
        try:
            self.progress.emit(5)
            seven_zip = self.find_7zip()
            if not seven_zip:
                message = "7-Zip (7z.exe) was not found! Please make sure 7-Zip is installed."
                return

            csc_path = self.find_csc()
            if not csc_path:
                message = "Windows .NET C# compiler (csc.exe) was not found!"
                return

            source_path = os.path.expandvars(self.cfg["source"].strip())
            if not os.path.exists(source_path):
                message = f"Source Folder / File path does not exist:\n{source_path}"
                return

            out_dir = os.path.expandvars(self.cfg["output"].strip())
            if not out_dir:
                message = "Please specify a valid Output save path!"
                return

            target_exe = self.resolve_output_exe_path()
            self.progress.emit(20)

            # No TemporaryDirectory finalizer: if an antivirus scanner briefly
            # holds payload.dat, retry cleanup instead of raising at Python exit.
            work_dir = tempfile.mkdtemp(prefix="byte_wrapper_build_")
            raw_7z = os.path.join(work_dir, "raw_package.7z")
            res_7z = self.build_7z_archive(seven_zip, source_path, raw_7z)
            if res_7z.returncode != 0:
                message = f"7-Zip Compression Error:\n{res_7z.stderr or res_7z.stdout}"
                return

            self.progress.emit(60)
            scrambled_dat = os.path.join(work_dir, "payload.dat")
            payload_path, scrambled = self.prepare_payload(raw_7z, scrambled_dat)
            self.progress.emit(75)

            ok, msg = self.compile_csharp_sfx(csc_path, work_dir, payload_path,
                                               scrambled, seven_zip, target_exe)
            if not ok:
                message = msg
                return

            self.progress.emit(100)
            success = True
            message = f"Package successfully created at:\n{target_exe}"

        except Exception as e:
            message = f"Unexpected error: {str(e)}"
        finally:
            if work_dir:
                _remove_build_directory_safely(work_dir)
            # Announce completion only AFTER source file handles close and
            # transient build-directory cleanup has been attempted.
            self.finished.emit(success, message)


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

        self.app_icon_path = get_app_icon_path()
        if not self.app_icon_path or not os.path.isfile(self.app_icon_path):
            fallback_ico = os.path.join(tempfile.gettempdir(), "byte_wrapper_default_box.ico")
            self._save_fallback_box_ico(fallback_ico)
            self.app_icon_path = fallback_ico

        self.current_icon_source = self.app_icon_path
        self.converted_ico_path = self.app_icon_path

        dpr = max(1.0, self.devicePixelRatioF())
        self.default_gui_icon = load_crisp_gui_icon(self.app_icon_path, dpr)
        self.setWindowIcon(self.default_gui_icon)
        if QApplication.instance():
            QApplication.instance().setWindowIcon(self.default_gui_icon)

        self._user_edited_name = False
        self._tracked_source_path = ""
        self._importing_config = False
        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._on_blink_step)
        self._blink_step_count = 0

        self.init_ui()
        self.apply_styles()

    def _save_fallback_box_ico(self, out_ico: str):
        draw_default_sfx_icon(out_ico)

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

        main_layout.addWidget(self._make_section_label("Name & Description"))
        nd_layout = QHBoxLayout()
        nd_layout.setContentsMargins(0, 0, 0, 0)
        nd_layout.setSpacing(8)

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
        nd_layout.addWidget(self.inp_name, stretch=1)

        self.inp_desc = QLineEdit()
        self.inp_desc.setPlaceholderText("Description...")
        self.inp_desc.setFixedHeight(34)
        nd_layout.addWidget(self.inp_desc, stretch=1)

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
        if checked and self.chk_hidden.isChecked():
            self.chk_hidden.setChecked(False)
        self.inp_run.setEnabled(not checked)
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
        """Compare folder selections independently of trailing separators or letter case."""
        path = path.strip().strip('"')
        if not path:
            return ""
        expanded = os.path.expanduser(os.path.expandvars(path))
        return os.path.normcase(os.path.abspath(os.path.normpath(expanded)))

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

    def on_source_dropped(self, path: str):
        """On a new folder clear immediately; on the same folder recheck Run File."""
        previous = self._tracked_source_path
        normalized = self._normalize_source_path(path)
        self.inp_source.setText(path)
        # setText does not emit textChanged when the same folder is dropped twice.
        if normalized == previous:
            self._revalidate_run_file_in_source()

    def _run_file_still_in_source(self) -> bool:
        """Only accept actual files under the selected source, not PATH or unrelated folders."""
        src = self._normalize_source_path(self.inp_source.text())
        candidate = self._extract_candidate_from_run_text(self.inp_run.text()).strip().strip('"')
        if not src or not candidate:
            return False
        candidate = os.path.expanduser(os.path.expandvars(candidate))
        if not os.path.exists(src):
            return False
        if os.path.isfile(src):
            candidate_path = candidate if os.path.isabs(candidate) else os.path.join(os.path.dirname(src), candidate)
            return (os.path.isfile(candidate_path) and
                    self._normalize_source_path(candidate_path) == src)

        if not os.path.isdir(src):
            return False
        candidate_path = candidate if os.path.isabs(candidate) else os.path.join(src, candidate)
        candidate_path = self._normalize_source_path(candidate_path)
        try:
            if os.path.commonpath((src, candidate_path)) != src:
                return False
        except ValueError:  # Different Windows drives
            return False
        if os.path.isfile(candidate_path):
            return True

        # A bare filename can be anywhere inside the source, matching the
        # existing icon lookup and the generated launcher's recursive lookup.
        if os.path.basename(candidate) == candidate and not os.path.isabs(candidate):
            for folder, _, files in os.walk(src):
                if any(name.casefold() == candidate.casefold() for name in files):
                    return True
        return False

    def _revalidate_run_file_in_source(self):
        if self.inp_run.text().strip() and not self._run_file_still_in_source():
            self._clear_source_dependent_fields()

    def on_name_manually_edited(self, text: str):
        self._user_edited_name = bool(text.strip())

    def _extract_candidate_from_run_text(self, raw: str) -> str:
        raw = raw.strip()
        if not raw:
            return ''
        if raw.startswith('"'):
            end_q = raw.find('"', 1)
            return raw[1:end_q] if end_q > 1 else raw.strip('"')
        match = re.match(r'^(.+?\.(?:bat|cmd|ps1|exe|msi|reg))(?=\s|$)', raw, re.IGNORECASE)
        if match:
            return match.group(1)
        return raw.split()[0]

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

        candidate = os.path.expandvars(self._extract_candidate_from_run_text(raw_run).replace("/", "\\"))
        if os.path.isfile(candidate):
            return candidate

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
            self._apply_icon_to_button(out_ico)
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

        if ext in (".exe", ".ico"):
            success = extract_icon_from_file(file_path, out_ico)
            if not success:
                self.btn_icon.setToolTip("Could not extract icon from the selected file.")
                return
        else:
            success = convert_image_to_ico(file_path, out_ico)
            if not success:
                self.btn_icon.setToolTip("Could not convert the selected image to .ico format.")
                return

        self.current_icon_source = file_path
        self.converted_ico_path = out_ico
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

            self._importing_config = True
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
                if icon_src.lower().endswith((".exe", ".ico")):
                    extract_icon_from_file(icon_src, out_ico)
                else:
                    convert_image_to_ico(icon_src, out_ico)
                if os.path.exists(out_ico):
                    self.current_icon_source = icon_src
                    self.converted_ico_path = out_ico
                    self._apply_icon_to_button(out_ico)
            else:
                self.current_icon_source = self.app_icon_path
                self.converted_ico_path = self.app_icon_path
                self._apply_icon_to_button(self.app_icon_path)

        except Exception as e:
            self.btn_import.setToolTip(f"Failed to import configuration: {e}")
        finally:
            self._importing_config = False

    def _source_run_file_path(self) -> str:
        """Resolve a selected run script inside Source Folder for a warning check."""
        source = os.path.expandvars(self.inp_source.text().strip())
        run = self._extract_candidate_from_run_text(self.inp_run.text()).strip().strip('"')
        if not run or not source:
            return ""
        run = os.path.expandvars(run)
        source_dir = source if os.path.isdir(source) else os.path.dirname(source)
        if os.path.isabs(run) and os.path.isfile(run):
            return run
        possible = os.path.join(source_dir, run)
        if os.path.isfile(possible):
            return possible
        # The launcher also supports a bare run filename under nested folders.
        if os.path.basename(run) == run and os.path.isdir(source_dir):
            for root, _, names in os.walk(source_dir):
                if run in names:
                    return os.path.join(root, run)
        return ""

    def start_process(self):
        cfg = self.collect_config()
        if not cfg["source"].strip():
            self.btn_start.setToolTip("Please specify a Source Folder or file.")
            return
        if not cfg["output"].strip():
            self.btn_start.setToolTip("Please specify an Output save directory.")
            return
        run_script_path = self._source_run_file_path()
        cfg["self_elevating_run_file"] = _looks_like_self_elevating_script(run_script_path)
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