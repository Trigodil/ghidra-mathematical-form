#!/usr/bin/env python3
"""Read-only, target-specific Bun graph extraction; never imports target modules."""

import argparse
import collections
import ctypes
import hashlib
import json
import mmap
import os
from pathlib import Path, PurePosixPath
import re
import struct


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lockdown", required=True)
    args = parser.parse_args()
    target = Path(args.binary).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    zstd = ctypes.CDLL("libzstd.so.1")
    zstd.ZSTD_getFrameContentSize.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    zstd.ZSTD_getFrameContentSize.restype = ctypes.c_ulonglong
    zstd.ZSTD_decompress.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    zstd.ZSTD_decompress.restype = ctypes.c_size_t
    zstd.ZSTD_isError.argtypes = [ctypes.c_size_t]
    zstd.ZSTD_isError.restype = ctypes.c_uint
    lock = ctypes.CDLL(str(Path(args.lockdown).resolve()))
    lock.analysis_lockdown.argtypes = [ctypes.c_char_p] * 3
    lock.analysis_lockdown(os.fsencode(target), b"", os.fsencode(output))
    with target.open("rb") as stream:
        data = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        assert header[0][:6] == b"\x7fELF\x02\x01"
        sections = [
            struct.unpack_from("<IIQQQQIIQQ", data, header[6] + i * header[11])
            for i in range(header[12])
        ]
        strings = sections[header[13]]
        names = data[strings[4] : strings[4] + strings[5]]
        section_rows = []
        for section in sections:
            name = names[section[0] :].split(b"\0", 1)[0].decode()
            assert section[1] == 8 or section[4] + section[5] <= len(data)
            section_rows.append(
                dict(
                    name=name,
                    offset=section[4],
                    size=section[5],
                    address=section[3],
                    flags=section[2],
                )
            )
        symbols = {}
        for section in sections:
            if section[1] not in (2, 11):
                continue
            strings = sections[section[6]]
            text = data[strings[4] : strings[4] + strings[5]]
            for offset in range(section[4], section[4] + section[5], section[9]):
                n, info, _, index, address, size = struct.unpack_from(
                    "<IBBHQQ", data, offset
                )
                if info & 15 == 2 and index and size:
                    name = text[n:].split(b"\0", 1)[0].decode()
                    symbols[(address, size)] = name
        symbol_rows = [
            dict(address=address, size=size, name=name)
            for (address, size), name in sorted(symbols.items())
        ]
        (output / "native_symbols.json").write_text(
            json.dumps(symbol_rows, indent=2) + "\n"
        )
        bun = next(row for row in section_rows if row["name"] == ".bun")
        start, length = bun["offset"], bun["size"]
        end = start + length
        magic = b"\n---- Bun! ----\n"
        assert data[end - len(magic) : end] == magic
        assert struct.unpack_from("<Q", data, start)[0] == length - 8
        base = start + 8
        footer = end - len(magic) - 32
        graph_size, table_offset, table_size, entry, argv_offset, argv_size, flags = (
            struct.unpack_from("<Q6I", data, footer)
        )
        assert base + graph_size == footer
        assert table_size % 52 == 0 and table_offset + table_size <= graph_size
        count = table_size // 52
        assert entry < count
        records, paths, seen, bytecode_ranges = [], set(), set(), []
        extensions = collections.Counter()
        import_edges = []

        def region(offset, size):
            assert 0 <= offset <= graph_size and 0 <= size <= graph_size - offset
            return data[base + offset : base + offset + size]

        for index in range(count):
            row = struct.unpack_from("<13I", data, base + table_offset + 52 * index)
            path = region(row[0], row[1]).rstrip(b"\0").decode("utf-8")
            assert path.startswith("/$bunfs/root/")
            relative = PurePosixPath(path[len("/$bunfs/root/") :])
            assert not relative.is_absolute() and ".." not in relative.parts
            assert str(relative) not in seen
            seen.add(str(relative))
            content = region(row[2], row[3])
            destination = output / "recovered" / str(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(0o600)
            assert (
                hashlib.sha256(destination.read_bytes()).digest()
                == hashlib.sha256(content).digest()
            )
            record = dict(
                index=index,
                path=path,
                extracted=str(destination.relative_to(output)),
                bytes=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
                content_offset=base + row[2],
                sourcemap_bytes=row[5],
                bytecode_offset=row[6],
                bytecode_span_bytes=row[7],
                flags=row[12],
            )
            decoded = content
            if content.startswith(b"\x28\xb5\x2f\xfd"):
                decoded_size = zstd.ZSTD_getFrameContentSize(content, len(content))
                assert decoded_size < 536870912, "Unknown or excessive decoded size"
                buffer = ctypes.create_string_buffer(decoded_size)
                result = zstd.ZSTD_decompress(
                    buffer, decoded_size, content, len(content)
                )
                assert not zstd.ZSTD_isError(result) and result == decoded_size
                decoded = buffer.raw
                decoded_relative = (
                    relative.with_suffix("") if relative.suffix == ".zst" else relative
                )
                decoded_path = output / "decompressed" / str(decoded_relative)
                decoded_path.parent.mkdir(parents=True, exist_ok=True)
                decoded_path.write_bytes(decoded)
                decoded_path.chmod(0o600)
                record["decompressed"] = str(decoded_path.relative_to(output))
                record["decompressed_bytes"] = len(decoded)
                record["decompressed_sha256"] = hashlib.sha256(decoded).hexdigest()
            if row[5]:
                source_map = region(row[4], row[5])
                destination.with_name(destination.name + ".map").write_bytes(source_map)
            if row[7]:
                assert row[6] <= graph_size and row[7] <= graph_size - row[6]
                bytecode_ranges.append((row[6], row[6] + row[7]))
            if relative.suffix == ".js" or index == entry:
                try:
                    text = decoded.decode("utf-8")
                except UnicodeDecodeError:
                    record["utf8"] = False
                else:
                    record["utf8"] = True
                    record["bytecode_directive"] = text.startswith("// @bun @bytecode")
                    for match in re.finditer(
                        r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"']+)["']""",
                        text,
                    ):
                        import_edges.append((path, match.group(1)))
            extensions[relative.suffix or "<none>"] += 1
            records.append(record)
            paths.add(path)
        merged = []
        for left, right in sorted(bytecode_ranges):
            if merged and left <= merged[-1][1]:
                merged[-1][1] = max(right, merged[-1][1])
            else:
                merged.append([left, right])
        for index, (left, right) in enumerate(merged):
            (output / f"bytecode-region-{index}.bin").write_bytes(
                region(left, right - left)
            )
        unresolved = sorted(
            {
                dependency
                for _, dependency in import_edges
                if dependency.startswith("/$bunfs/") and dependency not in paths
            }
        )
        (output / "modules.json").write_text(json.dumps(records, indent=2) + "\n")
        (output / "imports.json").write_text(
            json.dumps(
                dict(edges=import_edges, unresolved_absolute_bunfs=unresolved), indent=2
            )
            + "\n"
        )
        executable_bytes = sum(
            section["size"] for section in section_rows if section["flags"] & 4
        )
        summary = dict(
            binary=str(target),
            sha256=hashlib.sha256(data).hexdigest(),
            file_bytes=len(data),
            sections=section_rows,
            unique_named_function_ranges=len(symbol_rows),
            named_function_bytes=sum(row["size"] for row in symbol_rows),
            executable_section_bytes=executable_bytes,
            bun_graph_bytes=graph_size,
            module_count=count,
            entry_index=entry,
            entry_path=records[entry]["path"],
            extracted_content_bytes=sum(row["bytes"] for row in records),
            decompressed_assets=sum("decompressed" in row for row in records),
            decompressed_bytes=sum(row.get("decompressed_bytes", 0) for row in records),
            extension_counts=dict(extensions),
            modules_with_bytecode=sum(
                bool(row["bytecode_span_bytes"]) for row in records
            ),
            modules_with_sourcemap=sum(bool(row["sourcemap_bytes"]) for row in records),
            bytecode_unique_bytes=sum(right - left for left, right in merged),
            unresolved_absolute_bunfs_imports=len(unresolved),
            validation=f"All {count} graph records bounds checked; extracted content hashes checked against input slices.",
            scope="Bundled content extracted as stored; no target code executed. Native and JSC bytecode decompilation not established.",
        )
        (output / "inventory.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(
            json.dumps(
                {key: value for key, value in summary.items() if key != "sections"},
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
