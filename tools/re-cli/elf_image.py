"""Minimal little-endian ELF64 reader shared by the recovery tools."""

from pathlib import Path
import struct

# Relocation field widths in bytes; types absent here are four bytes wide.
RELOC_WIDTH = {1: 8, 12: 2, 13: 2, 14: 1, 15: 1, 24: 8, 25: 8, 31: 8, 33: 8}


class Elf:
    """Minimal little-endian ELF64 reader: sections, function symbols, rela."""

    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:4] != b"\x7fELF" or self.data[4] != 2 or self.data[5] != 1:
            raise ValueError(f"{path} is not a little-endian ELF64 file")
        shoff, = struct.unpack_from("<Q", self.data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", self.data, 0x3A)
        self.sections = []
        for index in range(shnum):
            fields = struct.unpack_from("<IIQQQQIIQQ", self.data, shoff + index * shentsize)
            self.sections.append(dict(zip(
                ("name", "type", "flags", "addr", "offset", "size", "link", "info", "align", "entsize"),
                fields,
            )))
        names = self.sections[shstrndx]
        for section in self.sections:
            section["name"] = self.string(names["offset"], section["name"])
        self.functions = self.read_functions()

    def string(self, table_offset, index):
        start = table_offset + index
        return self.data[start:self.data.index(b"\0", start)].decode("utf-8", "replace")

    def read_functions(self):
        functions = {}
        for section in self.sections:
            if section["type"] != 2:
                continue
            strtab = self.sections[section["link"]]
            for offset in range(section["offset"], section["offset"] + section["size"], 24):
                name, info, _, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, offset)
                if info & 0xF != 2 or not size or shndx == 0 or shndx >= len(self.sections):
                    continue
                functions.setdefault(self.string(strtab["offset"], name), []).append(
                    dict(section=shndx, address=value, size=size)
                )
        return functions

    def code(self, function):
        section = self.sections[function["section"]]
        start = section["offset"] + function["address"] - section["addr"]
        return self.data[start:start + function["size"]]

    def relocations(self, function):
        """Return (offset in function, width, type) for each relocation inside it."""
        found = []
        for section in self.sections:
            if section["type"] != 4 or section["info"] != function["section"]:
                continue
            for offset in range(section["offset"], section["offset"] + section["size"], 24):
                where, info, _ = struct.unpack_from("<QQq", self.data, offset)
                kind = info & 0xFFFFFFFF
                inside = where - function["address"]
                if kind and 0 <= inside < function["size"]:
                    found.append((inside, RELOC_WIDTH.get(kind, 4), kind))
        return found

    def section_ranges(self, names):
        """Address ranges of the named sections that exist in this image."""
        return [(s["addr"], s["addr"] + s["size"]) for s in self.sections
                if s["name"] in names and s["addr"]]

    def imports(self):
        """Map each GOT slot filled by a GLOB_DAT or JUMP_SLOT relocation to its symbol."""
        slots = {}
        for section in self.sections:
            if section["type"] != 4 or not section["link"]:
                continue
            symbols = self.sections[section["link"]]
            strtab = self.sections[symbols["link"]]
            for offset in range(section["offset"], section["offset"] + section["size"], 24):
                where, info, _ = struct.unpack_from("<QQq", self.data, offset)
                if info & 0xFFFFFFFF not in (6, 7) or not info >> 32:
                    continue
                entry = symbols["offset"] + (info >> 32) * 24
                name, = struct.unpack_from("<I", self.data, entry)
                slots[where] = self.string(strtab["offset"], name)
        return slots

    def plt_stubs(self, names=(".plt", ".plt.sec", ".plt.got")):
        """Map each PLT stub entry that jumps through a known GOT slot to its import."""
        slots, stubs = self.imports(), {}
        for section in self.sections:
            if section["name"] not in names or not section["addr"]:
                continue
            step = section["entsize"] or 16
            for start in range(0, section["size"], step):
                entry = self.data[section["offset"] + start:section["offset"] + start + step]
                jump = entry.find(b"\xff\x25")
                if jump < 0 or jump + 6 > len(entry):
                    continue
                disp, = struct.unpack_from("<i", entry, jump + 2)
                slot = section["addr"] + start + jump + 6 + disp
                if slot in slots:
                    stubs[section["addr"] + start] = slots[slot]
        return stubs

    def read(self, address, length):
        """Bytes of an initialized section at a virtual address, or None."""
        for section in self.sections:
            if (section["type"] == 1 and section["addr"] <= address and
                    address + length <= section["addr"] + section["size"]):
                start = section["offset"] + address - section["addr"]
                return self.data[start:start + length]
        return None

    def section_at(self, address):
        for section in self.sections:
            if section["addr"] and section["addr"] <= address < section["addr"] + section["size"]:
                return section
        return None

    def data_relocations(self):
        """Map a patched address to its target address (None when it names an import)."""
        if hasattr(self, "_relocated"):
            return self._relocated
        found = self._relocated = {}
        for section in self.sections:
            if section["type"] != 4:
                continue
            symbols = self.sections[section["link"]] if section["link"] else None
            for offset in range(section["offset"], section["offset"] + section["size"], 24):
                where, info, addend = struct.unpack_from("<QQq", self.data, offset)
                kind, index = info & 0xFFFFFFFF, info >> 32
                if kind == 8:
                    found[where] = addend
                elif kind in (1, 6) and index and symbols:
                    _, _, _, shndx, value, _ = struct.unpack_from("<IBBHQQ", self.data,
                                                                  symbols["offset"] + index * 24)
                    found[where] = value + addend if shndx else None
        return found

