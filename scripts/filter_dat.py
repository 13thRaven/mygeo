import json
import sys
from pathlib import Path


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def extract_country_code(msg: bytes) -> str:
    pos = 0
    end = len(msg)
    while pos < end:
        tag, pos = read_varint(msg, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = read_varint(msg, pos)
            return msg[pos : pos + length].decode("utf-8", errors="replace")
        if wire_type == 0:
            _, pos = read_varint(msg, pos)
        elif wire_type == 1:
            pos += 8
        elif wire_type == 2:
            length, pos = read_varint(msg, pos)
            pos += length
        elif wire_type == 5:
            pos += 4
        else:
            break
    return ""


def filter_dat(src_path: Path, dst_path: Path, allowed: set[str]) -> None:
    data = src_path.read_bytes()
    pos = 0
    end = len(data)
    out_chunks: list[bytes] = []
    found: set[str] = set()

    while pos < end:
        start = pos
        tag, pos = read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7

        if wire_type == 2:
            length, pos = read_varint(data, pos)
            msg = data[pos : pos + length]
            pos += length
            if field_num == 1:
                code = extract_country_code(msg).upper()
                if code in allowed:
                    out_chunks.append(data[start:pos])
                    found.add(code)
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type: {wire_type}")

    if not out_chunks:
        raise RuntimeError(f"Ни одна из категорий {sorted(allowed)} не найдена в {src_path.name}")

    dst_path.write_bytes(b"".join(out_chunks))
    missing = allowed - found
    print(f"[{src_path.name}] Сохранено категорий: {len(found)} ({sorted(found)})")
    if missing:
        print(f"[{src_path.name}] Предупреждение — не найдены: {sorted(missing)}")
    print(f"[{src_path.name}] Размер: {len(data) // 1024} KB -> {dst_path.stat().st_size // 1024} KB")


def main() -> None:
    config_path = Path(sys.argv[1])
    src_dir = Path(sys.argv[2])
    out_dir = Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)

    config = json.loads(config_path.read_text(encoding="utf-8"))

    for kind in ("geosite", "geoip"):
        categories = {c.strip().upper() for c in config.get(kind, []) if c.strip()}
        if not categories:
            continue
        filter_dat(src_dir / f"{kind}.dat", out_dir / f"{kind}.dat", categories)


if __name__ == "__main__":
    main()
