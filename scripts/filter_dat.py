import ipaddress
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

CDN_REPO_RAW = "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main"


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


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


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


def extract_entries(src_path: Path, allowed: set[str]) -> dict[str, bytes]:
    if not allowed:
        return {}

    data = src_path.read_bytes()
    pos = 0
    end = len(data)
    entries: dict[str, bytes] = {}

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
                    entries[code] = data[start:pos]
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            raise ValueError(f"Unsupported protobuf wire type: {wire_type}")

    missing = allowed - set(entries.keys())
    if missing:
        print(f"[{src_path.name}] Предупреждение — не найдены категории: {sorted(missing)}")

    return entries


def parse_cidr_msg(msg: bytes) -> tuple[bytes, int] | None:
    pos = 0
    end = len(msg)
    ip_bytes = b""
    prefix = 0
    while pos < end:
        tag, pos = read_varint(msg, pos)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 1 and wire_type == 2:
            length, pos = read_varint(msg, pos)
            ip_bytes = msg[pos : pos + length]
            pos += length
        elif field_num == 2 and wire_type == 0:
            prefix, pos = read_varint(msg, pos)
        elif wire_type == 0:
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
    return (ip_bytes, prefix) if ip_bytes else None


def extract_cidrs_from_entry(entry_chunk: bytes) -> set[tuple[bytes, int]]:
    _, pos = read_varint(entry_chunk, 0)
    length, pos = read_varint(entry_chunk, pos)
    msg = entry_chunk[pos : pos + length]

    cidrs: set[tuple[bytes, int]] = set()
    p = 0
    end = len(msg)
    while p < end:
        tag, p = read_varint(msg, p)
        field_num = tag >> 3
        wire_type = tag & 7
        if field_num == 2 and wire_type == 2:
            clen, p = read_varint(msg, p)
            parsed = parse_cidr_msg(msg[p : p + clen])
            if parsed:
                cidrs.add(parsed)
            p += clen
        elif wire_type == 0:
            _, p = read_varint(msg, p)
        elif wire_type == 1:
            p += 8
        elif wire_type == 2:
            clen, p = read_varint(msg, p)
            p += clen
        elif wire_type == 5:
            p += 4
        else:
            break
    return cidrs


def collapse_ipv4_cidrs(cidrs: set[tuple[bytes, int]]) -> list[tuple[bytes, int]]:
    v4_nets: list[ipaddress.IPv4Network] = []
    v6_cidrs: list[tuple[bytes, int]] = []

    for ip_bytes, prefix in cidrs:
        if len(ip_bytes) == 4:
            v4_nets.append(
                ipaddress.IPv4Network((ipaddress.IPv4Address(ip_bytes), prefix), strict=False)
            )
        elif len(ip_bytes) == 16:
            v6_cidrs.append((ip_bytes, prefix))

    collapsed_v4 = [
        (net.network_address.packed, net.prefixlen)
        for net in ipaddress.collapse_addresses(v4_nets)
    ]
    v6_cidrs.sort()
    return collapsed_v4 + v6_cidrs


def build_geoip_entry(code: str, cidrs: list[tuple[bytes, int]]) -> bytes:
    if not cidrs:
        raise RuntimeError(f"Категория {code} не содержит валидных IP/CIDR")

    code_bytes = code.upper().encode("utf-8")
    geoip_parts = [b"\x0a" + encode_varint(len(code_bytes)) + code_bytes]

    for ip_bytes, prefix in cidrs:
        cidr_msg = b"\x0a" + encode_varint(len(ip_bytes)) + ip_bytes
        if prefix:
            cidr_msg += b"\x10" + encode_varint(prefix)
        geoip_parts.append(b"\x12" + encode_varint(len(cidr_msg)) + cidr_msg)

    geoip_msg = b"".join(geoip_parts)
    return b"\x0a" + encode_varint(len(geoip_msg)) + geoip_msg


def fetch_cdn_ipv4(name: str) -> set[tuple[bytes, int]]:
    url = f"{CDN_REPO_RAW}/{name}/{name}_plain_ipv4.txt"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            text = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Не удалось скачать список '{name}' ({url}): HTTP {e.code}") from e

    cidrs: set[tuple[bytes, int]] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        net = ipaddress.ip_network(line, strict=False)
        if net.version == 4:
            cidrs.add((net.network_address.packed, net.prefixlen))

    if not cidrs:
        raise RuntimeError(f"Список '{name}' не содержит валидных IPv4-подсетей")
    return cidrs


def write_dat_and_index(out_dir: Path, kind: str, entries: dict[str, bytes]) -> None:
    if not entries:
        raise RuntimeError(f"Итоговый {kind}.dat пуст — проверьте categories.json")

    dat_path = out_dir / f"{kind}.dat"
    txt_path = out_dir / f"{kind}-categories.txt"

    ordered_codes = sorted(entries.keys())
    dat_path.write_bytes(b"".join(entries[c] for c in ordered_codes))
    txt_path.write_text("\n".join(c.lower() for c in ordered_codes) + "\n", encoding="utf-8")

    print(
        f"[{kind}.dat] Категорий: {len(ordered_codes)}, "
        f"размер: {dat_path.stat().st_size // 1024} KB -> {txt_path.name}"
    )


def main() -> None:
    config_path = Path(sys.argv[1])
    src_dir = Path(sys.argv[2])
    out_dir = Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)

    config = json.loads(config_path.read_text(encoding="utf-8"))

    # 1. Geosite
    geosite_allowed = {c.strip().upper() for c in config.get("geosite", []) if c.strip()}
    geosite_entries = extract_entries(src_dir / "geosite.dat", geosite_allowed)
    write_dat_and_index(out_dir, "geosite", geosite_entries)

    # 2. GeoIP (runetfreedom + только IPv4 из 123jjck/cdn-ip-ranges)
    geoip_allowed = {c.strip().upper() for c in config.get("geoip", []) if c.strip()}
    raw_geoip_entries = extract_entries(src_dir / "geoip.dat", geoip_allowed)

    geoip_cidrs: dict[str, set[tuple[bytes, int]]] = {
        code: extract_cidrs_from_entry(chunk) for code, chunk in raw_geoip_entries.items()
    }

    cdn_lists = [c.strip() for c in config.get("cdn_ip_ranges", []) if c.strip()]
    for name in cdn_lists:
        code = name.upper()
        cdn_cidrs = fetch_cdn_ipv4(name)
        if code in geoip_cidrs:
            before = len(geoip_cidrs[code])
            geoip_cidrs[code] |= cdn_cidrs
            print(
                f"[cdn-ip-ranges] Категория '{name}' объединена с geoip.dat "
                f"({before} + {len(cdn_cidrs)} -> {len(geoip_cidrs[code])} до агрегации)"
            )
        else:
            geoip_cidrs[code] = cdn_cidrs
            print(f"[cdn-ip-ranges] Загружена категория '{name}' ({len(cdn_cidrs)} IPv4-подсетей)")

    # 3. Агрегация IPv4-подсетей и сборка итогового geoip.dat
    geoip_entries: dict[str, bytes] = {}
    for code in sorted(geoip_cidrs.keys()):
        raw_set = geoip_cidrs[code]
        collapsed = collapse_ipv4_cidrs(raw_set)
        geoip_entries[code] = build_geoip_entry(code, collapsed)
        print(f"[geoip:{code.lower()}] Агрегация: {len(raw_set)} -> {len(collapsed)} подсетей")

    write_dat_and_index(out_dir, "geoip", geoip_entries)


if __name__ == "__main__":
    main()
