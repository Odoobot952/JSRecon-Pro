import json, os
MAX_COUNT = 5_000_000
MAX_BYTES = 2 * 1024 * 1024 * 1024
BASES = ["JSRECON_MARKER", "marker-12345", "sample_text", "probe_value"]
WRAPPERS = ["{}", "[]", "()", '"{}"', "'{}'", "prefix{}suffix"]
TRANSFORMS = [
    ("plain", lambda s: s),
    ("url-encoded-space", lambda s: s.replace(" ", "%20")),
    ("html-escaped", lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")),
    ("upper", lambda s: s.upper()),
    ("lower", lambda s: s.lower()),
]
LENGTHS = [1, 8, 32, 128, 512, 1024]

def iter_cases(count):
    if not 1 <= count <= MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")
    for i in range(count):
        base = BASES[i % len(BASES)]
        wrapper = WRAPPERS[(i // len(BASES)) % len(WRAPPERS)]
        name, transform = TRANSFORMS[(i // (len(BASES)*len(WRAPPERS))) % len(TRANSFORMS)]
        length = LENGTHS[(i // 140) % len(LENGTHS)]
        core = (base + "_" + str(i)).ljust(min(length, 1024), "x")[:min(length, 1024)]
        yield {"id": i+1, "category": name, "length": len(transform(wrapper.format(core))), "value": transform(wrapper.format(core))}

def write_corpus(count, output_path):
    if not 1 <= count <= MAX_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_COUNT}")
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    total = 0
    with open(output_path, "w", encoding="utf-8") as f:
        for case in iter_cases(count):
            line = json.dumps(case, ensure_ascii=False, separators=(",", ":")) + "\n"
            total += len(line.encode("utf-8"))
            if total > MAX_BYTES:
                raise ValueError("corpus exceeds 2 GB safety cap")
            f.write(line)
    return count
