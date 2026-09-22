from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int

    def contains_file_off(self, off: int) -> bool:
        return self.raw_ptr <= off < (self.raw_ptr + self.raw_size)

    def file_off_to_rva(self, off: int) -> int:
        return self.va + (off - self.raw_ptr)

    def rva_to_file_off(self, rva: int) -> int | None:
        if self.va <= rva < (self.va + max(self.vsize, self.raw_size)):
            return self.raw_ptr + (rva - self.va)
        return None


def parse_sections(data: bytes) -> tuple[int, list[Section]]:
    if data[:2] != b"MZ":
        raise ValueError("Not a PE file (missing MZ)")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\0\0":
        raise ValueError("Not a PE file (missing PE signature)")

    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == 0x10B:  # PE32
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
    elif magic == 0x20B:  # PE32+
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
    else:
        raise ValueError(f"Unknown optional header magic: {hex(magic)}")

    sec_off = opt_off + opt_size
    sections: list[Section] = []
    for i in range(num_sections):
        o = sec_off + i * 40
        raw_name = data[o : o + 8].split(b"\0", 1)[0]
        name = raw_name.decode(errors="ignore")
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, o + 8)
        sections.append(Section(name=name, va=va, vsize=vsize, raw_ptr=raw_ptr, raw_size=raw_size))
    return image_base, sections


def find_all(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def section_for_off(sections: list[Section], off: int) -> Section | None:
    for s in sections:
        if s.contains_file_off(off):
            return s
    return None


def scan_push_call_sites(data: bytes, text_off: int, text_size: int, target_va: int) -> list[dict]:
    """
    查找典型模式：
    - push imm32 == target_va ; call rel32
    - mov reg, imm32 == target_va ; push reg ; call rel32
    """
    out: list[dict] = []
    text = data[text_off : text_off + text_size]
    imm = struct.pack("<I", target_va & 0xFFFFFFFF)

    start = 0
    while True:
        idx = text.find(imm, start)
        if idx < 0:
            break

        # pattern 1: 68 <imm32> E8 <rel32>
        if idx >= 1 and idx + 8 < len(text) and text[idx - 1] == 0x68 and text[idx + 4] == 0xE8:
            rel = struct.unpack_from("<i", text, idx + 5)[0]
            call_site = text_off + idx + 4
            next_eip = call_site + 5
            callee = next_eip + rel
            out.append(
                {
                    "pattern": "push_imm_call",
                    "site_file_off": call_site,
                    "callee_file_off": callee,
                }
            )

        # pattern 2: B8..BF <imm32> 50..57 E8 <rel32>
        if (
            idx >= 1
            and idx + 9 < len(text)
            and 0xB8 <= text[idx - 1] <= 0xBF
            and 0x50 <= text[idx + 4] <= 0x57
            and text[idx + 5] == 0xE8
        ):
            rel = struct.unpack_from("<i", text, idx + 6)[0]
            call_site = text_off + idx + 5
            next_eip = call_site + 5
            callee = next_eip + rel
            out.append(
                {
                    "pattern": "mov_imm_push_reg_call",
                    "site_file_off": call_site,
                    "callee_file_off": callee,
                }
            )

        start = idx + 1

    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Locate string xrefs and possible push/call sites in PE.")
    parser.add_argument("--binary", required=True, help="Path to WXWork.exe")
    parser.add_argument("--needle", required=True, help="ASCII needle, e.g. message.db")
    parser.add_argument("--runtime-base", default="0xad0000", help="Runtime module base (hex), for runtime VA projection")
    parser.add_argument("--max-sites", type=int, default=40)
    parser.add_argument("--max-needle-hits", type=int, default=12, help="Upper bound of needle hits to analyze deeply")
    args = parser.parse_args()

    bin_path = Path(args.binary)
    data = bin_path.read_bytes()
    image_base, sections = parse_sections(data)
    runtime_base = int(args.runtime_base, 16)

    hits = find_all(data, args.needle.encode("ascii"))
    sec_text = next((s for s in sections if s.name == ".text"), None)
    if sec_text is None:
        raise ValueError(".text section not found")

    if len(hits) > args.max_needle_hits:
        hits = hits[: args.max_needle_hits]

    result_hits = []
    all_sites: list[dict] = []
    for off in hits:
        sec = section_for_off(sections, off)
        if sec is None:
            continue
        rva = sec.file_off_to_rva(off)
        preferred_va = image_base + rva
        runtime_va = runtime_base + rva
        item = {
            "needle_file_off": hex(off),
            "section": sec.name,
            "rva": hex(rva),
            "preferred_va": hex(preferred_va),
            "runtime_va_estimate": hex(runtime_va),
        }
        result_hits.append(item)
        sites = scan_push_call_sites(data, sec_text.raw_ptr, sec_text.raw_size, preferred_va)
        for s in sites:
            s["needle_preferred_va"] = hex(preferred_va)
            all_sites.append(s)

    # 去重并转换到 rva/runtime
    uniq = {}
    for s in all_sites:
        key = (s["pattern"], s["site_file_off"], s["callee_file_off"], s["needle_preferred_va"])
        uniq[key] = s
    sites_out = []
    for s in uniq.values():
        site_sec = section_for_off(sections, s["site_file_off"])
        callee_sec = section_for_off(sections, s["callee_file_off"])
        site_rva = site_sec.file_off_to_rva(s["site_file_off"]) if site_sec else None
        callee_rva = callee_sec.file_off_to_rva(s["callee_file_off"]) if callee_sec else None
        sites_out.append(
            {
                **s,
                "site_file_off": hex(s["site_file_off"]),
                "callee_file_off": hex(s["callee_file_off"]),
                "site_rva": hex(site_rva) if site_rva is not None else None,
                "callee_rva": hex(callee_rva) if callee_rva is not None else None,
                "site_runtime_va_estimate": hex(runtime_base + site_rva) if site_rva is not None else None,
                "callee_runtime_va_estimate": hex(runtime_base + callee_rva) if callee_rva is not None else None,
            }
        )

    payload = {
        "binary": str(bin_path),
        "needle": args.needle,
        "image_base": hex(image_base),
        "runtime_base": hex(runtime_base),
        "needle_hits": result_hits,
        "candidate_sites": sites_out[: args.max_sites],
        "candidate_site_count": len(sites_out),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
