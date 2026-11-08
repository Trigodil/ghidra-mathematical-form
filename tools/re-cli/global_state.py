"""Recover initialized non-executable data from native symbol evidence.

No declarations are guessed from identifier spelling. Relocations, conflicting
views and unavailable bytes remain explicit obligations. Overlapping supported
objects share one storage union instead of independent variables.
"""

import json
from bisect import bisect_right
import math
from pathlib import Path
import re
import struct

MAX_OBJECT = 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")
RECOVERED_OBJECT = re.compile(r"__recovery_(?:object|string)_[0-9a-f]+")
INTEGER_TYPES = {
    "byte": 1,
    "char": 1,
    "uchar": 1,
    "short": 2,
    "ushort": 2,
    "int": 4,
    "uint": 4,
    "long": 8,
    "ulong": 8,
    "longlong": 8,
    "ulonglong": 8,
}
for _width in (1, 2, 4, 8, 16):
    for _prefix in ("int", "uint", "undefined", "xunknown"):
        INTEGER_TYPES[f"{_prefix}{_width}"] = _width
INTEGER_TYPES["undefined"] = 1
FLOAT_TYPES = {"float": 4, "double": 8, "float4": 4, "float8": 8}


def declaration_shape(record):
    """Accept one simple declaration, preserving its native-inferred width."""
    name = record.get("name")
    if not isinstance(name, str) or not NAME.fullmatch(name):
        return None
    declaration = record.get("declaration", "").strip()
    match = re.fullmatch(
        r"(const\s+)?([A-Za-z_][A-Za-z_0-9]*)\s*(\*\s*)?\b"
        + re.escape(name)
        + r"\s*(?:\[\s*(\d+)\s*\])?\s*;",
        declaration,
    )
    if not match:
        return None
    qualifier, ctype, pointer, count = match.groups()
    count = int(count) if count else None
    width = (
        8
        if pointer
        else INTEGER_TYPES.get(
            ctype, FLOAT_TYPES.get(ctype, 1 if ctype == "bool" else None)
        )
    )
    if width is None or count == 0 or (count or 1) * width != record["size"]:
        return None
    return dict(
        ctype=(qualifier or "") + ctype + (" *" if pointer else ""),
        base_type=ctype,
        pointer=bool(pointer),
        count=count,
        width=width,
    )


def number(value, ctype, width):
    if width <= 8:
        return f"({ctype})0x{value:x}ULL"
    return f"({ctype})(((uint16)0x{value >> 64:x}ULL << 64) | (uint16)0x{value & ((1 << 64)-1):x}ULL)"


def literal_pointer(record, extents):
    """True when known bytes hold a pointer value that names no recovered object."""
    target = record["pointer_target"]
    return (
        record.get("initial_status") == "known"
        and target is not None
        and not record["pointer_target_is_code"]
        and not any(start <= target < end for start, end in extents)
    )


def initializer(record, shape, literal=False):
    raw = bytes.fromhex(record["initial_hex"])
    values = []
    for offset in range(0, len(raw), shape["width"]):
        chunk = raw[offset : offset + shape["width"]]
        value = int.from_bytes(chunk, "little")
        if shape["pointer"]:
            if value and not literal:
                return None, "pointer_requires_reference"
            values.append(number(value, shape["ctype"], 8) if value else "0")
        elif shape["base_type"] == "bool":
            if value not in (0, 1):
                return None, "noncanonical_boolean"
            values.append("true" if value else "false")
        elif shape["base_type"] in FLOAT_TYPES:
            floating = struct.unpack("<f" if len(chunk) == 4 else "<d", chunk)[0]
            if not math.isfinite(floating):
                return None, "nonfinite_float_payload"
            values.append(floating.hex() + ("f" if len(chunk) == 4 else ""))
        else:
            values.append(number(value, shape["ctype"], shape["width"]))
    return (
        "{" + ", ".join(values) + "}" if shape["count"] is not None else values[0]
    ), None


def relocated_words(record, image):
    """Split a byte array holding relocated pointers into (word, target) pairs, or None."""
    if (image is None or record.get("initial_status") != "relocation_requires_resolution"
            or record.get("pointer_target") is not None or record["size"] % 8
            or not re.fullmatch(r"\s*xunknown1\s+\w+\s*\[\s*\d+\s*\]\s*;", record.get("declaration", ""))):
        return None
    raw = image.read(record["address"], record["size"])
    if raw is None:
        return None
    patched = image.data_relocations()
    words = []
    for offset in range(0, record["size"], 8):
        address = record["address"] + offset
        if address in patched and patched[address] is None:
            return None
        words.append((int.from_bytes(raw[offset:offset + 8], "little"), patched.get(address)))
    return words


def pointer_retyped(declaration, name, source):
    """Declare an 8-byte integer global as a pointer when the code dereferences or indexes it."""
    match = re.fullmatch(r"([A-Za-z_]\w*)\s+" + re.escape(name) + r"\s*;", declaration)
    if not match or INTEGER_TYPES.get(match[1]) != 8:
        return declaration
    use = re.compile(rf"\b{re.escape(name)}\s*\[|(?<![\w)\]])\s*\*\s*\(?\s*{re.escape(name)}\b")
    return f"{match[1]} *{name};" if use.search(source) else declaration


def recover(base, rows, functions=None, source="", image=None):
    functions = functions or {}
    records, obligations, metadata_missing = {}, [], []
    consumed = 0
    for row in rows:
        path = Path(base) / "functions" / f'{row["address"]:x}' / "globals.json"
        if not path.is_file():
            metadata_missing.append(row["address"])
            continue
        try:
            if path.stat().st_size > MAX_TOTAL * 3:
                raise ValueError("metadata_size_limit")
            data = json.loads(path.read_text())
            if data.get("version") not in (1, 2) or not isinstance(
                data.get("globals"), list
            ):
                raise ValueError("unsupported_metadata")
            for original in data["globals"]:
                record = dict(original)
                name, address, size = (
                    record.get("name"),
                    record.get("address"),
                    record.get("size"),
                )
                if (
                    not isinstance(name, str)
                    or type(address) is not int
                    or type(size) is not int
                    or address < 0
                    or size < 1
                    or size > MAX_OBJECT
                    or address + size > 2**64
                ):
                    raise ValueError("invalid_global_extent")
                if record.get("initial_status") == "known":
                    raw = record.get("initial_hex")
                    if (
                        not isinstance(raw, str)
                        or len(raw) != size * 2
                        or re.fullmatch("[0-9a-fA-F]+", raw) is None
                    ):
                        raise ValueError("invalid_initial_bytes")
                    record["initial_hex"] = raw.lower()
                if re.fullmatch(r"[A-Za-z_]\w*(?:\.\w+)+", name):
                    # Local symbols such as ML_Code.0 become identifiers, as for function clones.
                    record["declaration"] = record.get("declaration", "").replace(name, name.replace(".", "_"))
                    name = record["name"] = name.replace(".", "_")
                record["declaration"] = pointer_retyped(
                    " ".join(record.get("declaration", "").split()), name, source
                )
                record.setdefault("pointer_target", None)
                record.setdefault("pointer_target_is_code", False)
                if type(record["pointer_target_is_code"]) is not bool:
                    raise ValueError("invalid_pointer_target_kind")
                target = record["pointer_target"]
                if target is not None and (
                    type(target) is not int or not 0 <= target < 2**64
                ):
                    raise ValueError("invalid_pointer_target")
                if (
                    target is not None
                    and record.get("initial_status") == "known"
                    and (
                        size != 8
                        or int.from_bytes(
                            bytes.fromhex(record["initial_hex"]), "little"
                        )
                        != target
                    )
                ):
                    raise ValueError("pointer_target_disagrees_with_bytes")
                record.pop("type_name", None)
                previous = records.get(name)
                if previous is not None and RECOVERED_OBJECT.fullmatch(name):
                    # Extents come from per-function evidence, so the longest view of an address wins.
                    if record["size"] > previous["size"]:
                        consumed += record["size"] - previous["size"]
                        records[name] = record
                    continue
                if previous is not None:
                    ignored = {"pointer_target", "pointer_target_is_code", "conflict"}
                    same = {k: v for k, v in previous.items() if k not in ignored} == {
                        k: v for k, v in record.items() if k not in ignored
                    }
                    targets = (previous.get("pointer_target"), target)
                    compatible = (
                        targets[0] is None
                        or targets[1] is None
                        or targets[0] == targets[1]
                    )
                    if targets[0] is not None and targets[1] is not None:
                        compatible = (
                            compatible
                            and previous["pointer_target_is_code"]
                            == record["pointer_target_is_code"]
                        )
                    if not same or not compatible:
                        if not previous.get("conflict"):
                            obligations.append(
                                dict(name=name, reason="inconsistent_global_views")
                            )
                        previous["conflict"] = True
                    elif target is not None:
                        previous["pointer_target"] = target
                        previous["pointer_target_is_code"] = record[
                            "pointer_target_is_code"
                        ]
                elif previous is None:
                    consumed += size
                    if consumed > MAX_TOTAL:
                        obligations.append(dict(name=name, reason="global_byte_budget"))
                        continue
                    records[name] = record
        except (OSError, ValueError, TypeError, AttributeError) as error:
            obligations.append(
                dict(
                    function=row["address"],
                    reason="invalid_global_metadata",
                    detail=str(error),
                )
            )
    accepted, relocated = [], {}
    blocked = set()
    extents = [(r["address"], r["address"] + r["size"]) for r in records.values()]
    relocated_arrays = {}
    for name, record in records.items():
        words = relocated_words(record, image)
        if words is not None:
            relocated_arrays[name] = words
    # A relocated target no recovered object holds becomes a string object, so that it is a
    # neighbour of the objects around it rather than a separate placement.
    if image is not None:
        wanted = {r["pointer_target"] for r in records.values()
                  if r.get("pointer_target") is not None and not r["pointer_target_is_code"]
                  and r.get("initial_status") != "known" and r["size"] == 8}
        for words in relocated_arrays.values():
            wanted.update(t for _, t in words if t is not None and t not in functions)
        for target in sorted(wanted):
            if any(start <= target < end for start, end in extents):
                continue
            section = image.section_at(target)
            raw = section and image.read(target, min(4096, section["addr"] + section["size"] - target))
            end = raw.find(b"\0") if raw else -1
            if end < 0 or section["flags"] & 5 or not section["flags"] & 2:
                continue
            name = f"__recovery_string_{target:x}"
            records.setdefault(name, dict(
                name=name, address=target, size=end + 1, declaration=f"char {name} [{end + 1}];",
                initial_status="known", initial_hex=raw[: end + 1].hex(), pointer_target=None,
                pointer_target_is_code=False))
            extents.append((target, target + end + 1))
    for name, record in records.items():
        if name in relocated_arrays:
            continue
        reason = (
            record.get("initial_status", "missing_initial_state")
            if record.get("initial_status") != "known"
            else None
        )
        if record.get("conflict"):
            reason = "inconsistent_global_views"
        shape = declaration_shape(record)
        if shape is None:
            reason = reason or "unsupported_global_declaration"
        value = None
        if (
            reason in (None, "relocation_requires_resolution")
            and shape is not None
            and shape["count"] is None
            and shape["width"] == 8
            and record["pointer_target"] is not None
            and (shape["pointer"] or shape["base_type"] in INTEGER_TYPES)
            and not record.get("conflict")
            and not literal_pointer(record, extents)
        ):
            relocated[name] = record["pointer_target"]
            reason = None
            value = ""
        if reason is None:
            if name not in relocated:
                value, reason = initializer(
                    record, shape, literal_pointer(record, extents)
                )
        if reason:
            blocked.add(name)
            obligations.append(
                dict(name=name, address=record["address"], reason=reason)
            )
        else:
            accepted.append(dict(record=record, shape=shape, value=value))
    # Views of one relocated word with the same extent and target share the first view's storage.
    twins, by_extent = {}, {}
    for name in sorted(relocated):
        r = records[name]
        key = (r["address"], r["size"], relocated[name], r["pointer_target_is_code"])
        by_extent.setdefault(key, []).append(name)
    for names in by_extent.values():
        primary = min(names, key=lambda n: (not declaration_shape(records[n])["pointer"], n))
        twins.update({n: primary for n in names if n != primary})
    for name in twins:
        del relocated[name]
    accepted = [item for item in accepted if item["record"]["name"] not in twins]
    # An unresolved overlapping view cannot safely be split off from a known one.
    components = []
    for record in sorted((r for r in records.values() if r["name"] not in twins),
                         key=lambda r: (r["address"], r["size"])):
        if not components or record["address"] >= components[-1]["end"]:
            components.append(
                dict(end=record["address"] + record["size"], names=[record["name"]])
            )
        else:
            components[-1]["end"] = max(
                components[-1]["end"], record["address"] + record["size"]
            )
            components[-1]["names"].append(record["name"])
    for component in components:
        if len(component["names"]) > 1 and any(
            name in relocated for name in component["names"]
        ):
            for name in component["names"]:
                blocked.add(name)
                obligations.append(
                    dict(name=name, reason="relocated_overlap_requires_resolution")
                )
        if any(name in blocked for name in component["names"]):
            for name in component["names"]:
                if name not in blocked:
                    blocked.add(name)
                    obligations.append(
                        dict(name=name, reason="overlaps_unresolved_global")
                    )
    accepted = [item for item in accepted if item["record"]["name"] not in blocked]
    pointer_items = [item for item in accepted if item["record"]["name"] in relocated]
    accepted = [item for item in accepted if item["record"]["name"] not in relocated]
    accepted.sort(key=lambda item: (item["record"]["address"], item["record"]["name"]))
    groups = []
    for item in accepted:
        r = item["record"]
        # Recovered objects that touch share one placement, so their distances hold.
        touching = (groups and r["address"] == groups[-1]["end"] and RECOVERED_OBJECT.fullmatch(r["name"])
                    and RECOVERED_OBJECT.fullmatch(groups[-1]["items"][-1]["record"]["name"]))
        if not groups or (r["address"] >= groups[-1]["end"] and not touching):
            groups.append(
                dict(start=r["address"], end=r["address"] + r["size"], items=[item])
            )
        else:
            groups[-1]["end"] = max(groups[-1]["end"], r["address"] + r["size"])
            groups[-1]["items"].append(item)
    declarations, exported = [], []
    for index, group in enumerate(groups):
        if len(group["items"]) == 1:
            item = group["items"][0]
            record = item["record"]
            declarations.append(
                record["declaration"].rstrip(";") + " = " + item["value"] + ";"
            )
            exported.append(record["name"])
            continue
        size = group["end"] - group["start"]
        raw = bytearray(size)
        known = bytearray(size)
        fields = []
        aliases = []
        conflict = False
        for view, item in enumerate(group["items"]):
            r, shape = item["record"], item["shape"]
            offset = r["address"] - group["start"]
            content = bytes.fromhex(r["initial_hex"])
            for byte, value in enumerate(content, offset):
                if known[byte] and raw[byte] != value:
                    conflict = True
                raw[byte] = value
                known[byte] = 1
            pad = f"unsigned char pad[{offset}]; " if offset else ""
            suffix = f'[{shape["count"]}]' if shape["count"] is not None else ""
            fields.append(
                f'  struct __attribute__((packed)) {{ {pad}{shape["ctype"]} value{suffix}; }} view{view};'
            )
            aliases.append(
                f'#define {r["name"]} (__recovery_data_{index}.view{view}.value)'
            )
        if conflict or not all(known):
            obligations.extend(
                dict(name=item["record"]["name"], reason="conflicting_overlap_bytes")
                for item in group["items"]
            )
            continue
        # GNU C union views explicitly preserve aliases and partial overlaps.
        declarations.append(
            "static union {\n"
            + f"  unsigned char raw[{size}];\n"
            + "\n".join(fields)
            + f"\n}} __recovery_data_{index} = {{ .raw = {{"
            + ",".join(f"0x{b:02x}" for b in raw)
            + "} };"
        )
        declarations.extend(aliases)
        exported.extend(item["record"]["name"] for item in group["items"])
    # Emit initialized pointer references after data storage and aliases exist.
    # Forward declarations permit mutually referring pointer objects.
    pointer_names = {item["record"]["name"] for item in pointer_items}
    available_names = set(exported) | pointer_names | set(relocated_arrays)
    address_objects = sorted(
        (r for r in records.values() if r["name"] in available_names),
        key=lambda r: (r["address"], r["name"]),
    )
    starts, max_ends = [], []
    for record in address_objects:
        starts.append(record["address"])
        max_ends.append(
            max(max_ends[-1] if max_ends else 0, record["address"] + record["size"])
        )
    references = {}
    for item in pointer_items:
        record, shape = item["record"], item["shape"]
        target = record["pointer_target"]
        name = record["name"]
        if record["pointer_target_is_code"]:
            destination = functions.get(target)
            if destination:
                references[name] = dict(
                    value=f'({shape["ctype"]})&{destination}', dependency=None
                )
        else:
            possible = []
            position = bisect_right(starts, target) - 1
            while position >= 0 and max_ends[position] > target:
                other = address_objects[position]
                if target < other["address"] + other["size"]:
                    possible.append(other)
                position -= 1
            if possible:
                other = min(possible, key=lambda r: (r["size"], r["name"]))
                offset = target - other["address"]
                references[name] = dict(
                    value=f'({shape["ctype"]})((unsigned char *)&{other["name"]} + {offset})',
                    dependency=other["name"],
                )
            else:
                past = [o for o in address_objects if o["address"] + o["size"] == target]
                if past:
                    other = min(past, key=lambda r: (r["size"], r["name"]))
                    references[name] = dict(
                        value=f'({shape["ctype"]})((unsigned char *)&{other["name"]} + {other["size"]})',
                        dependency=other["name"],
                    )
        if name not in references:
            blocked.add(name)
            obligations.append(
                dict(name=name, reason="relocation_target_not_recovered", target=target)
            )
    changed = True
    while changed:
        changed = False
        for name, reference in references.items():
            if name not in blocked and reference["dependency"] in blocked:
                blocked.add(name)
                changed = True
                obligations.append(
                    dict(name=name, reason="relocation_dependency_unresolved")
                )
    array_declarations = []
    for name, words in relocated_arrays.items():
        record = records[name]
        values = []
        for index, (word, target) in enumerate(words):
            if target is None:
                values.append(f"0x{word:x}UL")
                continue
            possible = [
                other for other in address_objects
                if other["name"] not in blocked and other["address"] <= target < other["address"] + other["size"]
            ]
            if possible:
                other = min(possible, key=lambda r: (r["size"], r["name"]))
                values.append(f'(unsigned long)((unsigned char *)&{other["name"]} + {target - other["address"]})')
            elif functions.get(target):
                values.append(f"(unsigned long)&{functions[target]}")
            elif any(o["address"] + o["size"] == target and o["name"] not in blocked for o in address_objects):
                other = min((o for o in address_objects if o["address"] + o["size"] == target and o["name"] not in blocked),
                            key=lambda r: (r["size"], r["name"]))
                values.append(f'(unsigned long)((unsigned char *)&{other["name"]} + {other["size"]})')
            else:
                values = None
                obligations.append(dict(name=name, reason="relocation_target_not_recovered", target=target))
                break
        if values is not None:
            array_declarations.append(f"unsigned long __recovery_words_{name}[{len(values)}] = {{{', '.join(values)}}};")
            array_declarations.append(
                f'extern {record["declaration"].rstrip(";")} __attribute__((alias("__recovery_words_{name}")));'
            )
            exported.append(name)
    declarations.extend(
        "extern " + item["record"]["declaration"]
        for item in pointer_items
        if item["record"]["name"] not in blocked
    )
    for item in pointer_items:
        record = item["record"]
        name = record["name"]
        if name in blocked:
            continue
        declarations.append(
            record["declaration"].rstrip(";") + " = " + references[name]["value"] + ";"
        )
        exported.append(name)
    for name, primary in sorted(twins.items()):
        if primary in exported:
            declarations.append(
                f'extern {records[name]["declaration"].rstrip(";")} __attribute__((alias("{primary}")));'
            )
            exported.append(name)
    declarations.extend(array_declarations)
    # Unrecovered storage stays an explicit external symbol, never invented data.
    external = []
    for name, record in records.items():
        declaration = record["declaration"]
        if (
            name not in exported
            and declaration.endswith(";")
            and re.search(r"\b" + re.escape(name) + r"\b", declaration)
        ):
            declarations.append("extern " + declaration)
            external.append(name)
    return "\n".join(declarations), dict(
        exported_globals=exported,
        external_globals=external,
        obligations=obligations,
        functions_without_metadata=metadata_missing,
        source_global_equivalence_proved=False,
    )


GHIDRA_GLOBAL = re.compile(r"\b([a-z]{1,3})Ram([0-9a-f]{16})\b")
GHIDRA_PREFIX_TYPES = {
    "x": "xunknown8",
    "i": "int8",
    "u": "uint8",
    "f": "float8",
    "c": "char",
    "pc": "code *",
    "pu": "uint8 *",
    "pi": "int8 *",
    "px": "xunknown8 *",
}


def declare_missing(source, declared):
    """Declare address-named globals that carry no native metadata.

    The type comes only from the decompiler's name prefix; each one is reported.
    """
    names = {}
    for match in GHIDRA_GLOBAL.finditer(source):
        name, prefix = match.group(0), match.group(1)
        if name not in declared and prefix in GHIDRA_PREFIX_TYPES:
            names[name] = GHIDRA_PREFIX_TYPES[prefix]
    declarations = [f"extern {ctype} {name};" for name, ctype in sorted(names.items())]
    return "\n".join(declarations), sorted(names)
