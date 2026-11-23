"""
Скрипт для сборки облегчённых файлов geosite.dat и geoip.dat.

Что он делает:
1. Берёт большие исходные файлы geosite.dat и geoip.dat и вырезает из них
   только те категории, которые перечислены в categories.json.
2. Скачивает дополнительные списки IPv4-адресов из репозитория 123jjck/cdn-ip-ranges.
3. Если имя категории совпало, объединяет адреса без дубликатов.
4. «Схлопывает» (агрегирует) соседние и пересекающиеся IPv4-подсети, чтобы
   итоговый geoip.dat весил меньше и быстрее обрабатывался клиентами.
5. Сохраняет готовые .dat-файлы и текстовые списки всех вошедших в них категорий.

Небольшая справка по формату .dat:
Файлы geosite.dat и geoip.dat хранятся в бинарном формате Protobuf (Google Protocol Buffers).
Вместо текстовых скобок и кавычек (как в JSON) там идут компактные байтовые блоки:
[заголовок поля (номер + тип)] -> [длина данных] -> [сами данные].
Скрипт читает эти блоки напрямую, поэтому ему не нужны внешние библиотеки.
"""

import ipaddress  # Стандартный модуль Python для работы с IP-адресами и подсетями (CIDR)
import json  # Для чтения файла настроек categories.json
import sys  # Для получения аргументов, переданных скрипту из командной строки
import urllib.error  # Для перехвата сетевых ошибок (например, 404 Not Found)
import urllib.request  # Для скачивания текстовых списков IP из интернета
from pathlib import Path  # Удобная работа с путями к файлам и папкам

# Базовая ссылка на "сырые" (raw) файлы репозитория со списками CDN и хостеров
CDN_REPO_RAW = "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/main"


# =============================================================================
# БЛОК 1. Низкоуровневая работа с числами в формате Protobuf (Varint)
# =============================================================================

def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """
    Читает число в формате varint из массива байтов buf, начиная с позиции pos.
    Varint — способ экономии места: маленькие числа занимают 1 байт, большие — несколько.
    Если старший бит байта равен 1 (0x80), значит число продолжается в следующем байте.
    Возвращает кортеж: (прочитанное_число, новая_позиция_в_файле).
    """
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        # Берём младшие 7 бит байта и добавляем к результату с нужным сдвигом
        result |= (b & 0x7F) << shift
        # Если старший бит равен 0 — это был последний байт числа, выходим
        if not (b & 0x80):
            return result, pos
        shift += 7


def encode_varint(value: int) -> bytes:
    """
    Обратная операция: превращает обычное целое число Python в байты формата varint.
    Используется при сборке нового файла geoip.dat.
    """
    out = bytearray()
    while value > 0x7F:
        # Записываем 7 бит числа и ставим старший бит в 1 (признак продолжения)
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    # Последний байт записываем со старшим битом 0
    out.append(value)
    return bytes(out)


# =============================================================================
# БЛОК 2. Чтение и фильтрация категорий из исходных .dat-файлов
# =============================================================================

def extract_country_code(msg: bytes) -> str:
    """
    Извлекает имя категории (в терминологии V2Ray оно называется country_code,
    например 'RU-BLOCKED' или 'YOUTUBE') из одного бинарного блока категории.
    """
    pos = 0
    end = len(msg)
    while pos < end:
        # Читаем заголовок поля: в нём зашиты номер поля (field_num) и его тип (wire_type)
        tag, pos = read_varint(msg, pos)
        field_num = tag >> 3
        wire_type = tag & 7

        # Поле №1 с типом 2 (строка/байты) — это и есть имя категории
        if field_num == 1 and wire_type == 2:
            length, pos = read_varint(msg, pos)
            return msg[pos : pos + length].decode("utf-8", errors="replace")

        # Если встретилось другое поле — просто перепрыгиваем через него, зная его размер
        if wire_type == 0:  # Тип 0: число varint
            _, pos = read_varint(msg, pos)
        elif wire_type == 1:  # Тип 1: фиксированные 8 байт
            pos += 8
        elif wire_type == 2:  # Тип 2: строка или вложенный блок (сначала длина, потом данные)
            length, pos = read_varint(msg, pos)
            pos += length
        elif wire_type == 5:  # Тип 5: фиксированные 4 байта
            pos += 4
        else:
            break
    return ""


def extract_entries(src_path: Path, allowed: set[str]) -> dict[str, bytes]:
    """
    Проходит по исходному .dat-файлу и вырезает из него только те категории,
    чьи имена есть в множестве allowed.
    Возвращает словарь: {"ИМЯ_КАТЕГОРИИ": сырые_байты_этой_категории}.
    """
    if not allowed:
        return {}

    data = src_path.read_bytes()
    pos = 0
    end = len(data)
    entries: dict[str, bytes] = {}

    while pos < end:
        # Запоминаем начало блока, чтобы потом вырезать его целиком без пересборки
        start = pos
        tag, pos = read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 7

        if wire_type == 2:
            length, pos = read_varint(data, pos)
            msg = data[pos : pos + length]
            pos += length
            # На верхнем уровне .dat-файла каждая запись (категория) лежит в поле №1
            if field_num == 1:
                code = extract_country_code(msg).upper()
                if code in allowed:
                    # Сохраняем блок в точности так, как он лежал в исходном файле
                    entries[code] = data[start:pos]
        elif wire_type == 0:
            _, pos = read_varint(data, pos)
        elif wire_type == 1:
            pos += 8
        elif wire_type == 5:
            pos += 4
        else:
            raise ValueError(f"Неподдерживаемый тип поля Protobuf: {wire_type}")

    # Проверяем, не ошибся ли пользователь в названии какой-нибудь категории
    missing = allowed - set(entries.keys())
    if missing:
        print(f"[{src_path.name}] Предупреждение — не найдены категории: {sorted(missing)}")

    return entries


# =============================================================================
# БЛОК 3. Разбор, схлопывание (агрегация) и сборка IP-подсетей для geoip.dat
# =============================================================================

def parse_cidr_msg(msg: bytes) -> tuple[bytes, int] | None:
    """
    Разбирает одну запись подсети (CIDR) из бинарного формата GeoIP.
    Внутри лежат два поля:
      - поле №1: IP-адрес в виде байтов (4 байта для IPv4, 16 байт для IPv6)
      - поле №2: длина префикса / маска подсети (например, 24 для /24)
    Возвращает кортеж (байты_IP, маска) или None, если запись повреждена.
    """
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
    """
    Достаёт все IP-подсети из одного бинарного блока категории geoip.dat.
    Используется, чтобы потом объединить и схлопнуть их с другими списками.
    """
    # Пропускаем внешний заголовок записи и получаем внутреннее содержимое категории
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
        # Внутри категории GeoIP каждая подсеть лежит в поле №2 с типом 2
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
    """
    Оптимизирует (агрегирует) список подсетей:
    - Например, две соседние сети 1.1.1.0/25 и 1.1.1.128/25 объединятся в одну 1.1.1.0/24.
    - Вложенные сети и дубликаты будут автоматически удалены.
    Если в категории из geoip.dat были IPv6-адреса, они аккуратно сохранятся в конце списка.
    """
    v4_nets: list[ipaddress.IPv4Network] = []
    v6_cidrs: list[tuple[bytes, int]] = []

    for ip_bytes, prefix in cidrs:
        if len(ip_bytes) == 4:  # 4 байта = IPv4
            # strict=False позволяет корректно обработать адреса, где не обнулена хостовая часть
            v4_nets.append(
                ipaddress.IPv4Network((ipaddress.IPv4Address(ip_bytes), prefix), strict=False)
            )
        elif len(ip_bytes) == 16:  # 16 байт = IPv6
            v6_cidrs.append((ip_bytes, prefix))

    # Встроенная функция collapse_addresses делает всю математику по схлопыванию подсетей
    collapsed_v4 = [
        (net.network_address.packed, net.prefixlen)
        for net in ipaddress.collapse_addresses(v4_nets)
    ]
    v6_cidrs.sort()
    return collapsed_v4 + v6_cidrs


def build_geoip_entry(code: str, cidrs: list[tuple[bytes, int]]) -> bytes:
    """
    Собирает список IP-подсетей обратно в бинарный блок формата Protobuf для geoip.dat.
    Байты-метки (теги Protobuf):
      b"\\x0a" — поле №1, тип 2 (строка или байты)
      b"\\x10" — поле №2, тип 0 (целое число varint)
      b"\\x12" — поле №2, тип 2 (вложенный блок CIDR)
    """
    if not cidrs:
        raise RuntimeError(f"Категория {code} не содержит валидных IP/CIDR")

    # Записываем имя категории в поле №1
    code_bytes = code.upper().encode("utf-8")
    geoip_parts = [b"\x0a" + encode_varint(len(code_bytes)) + code_bytes]

    # Кодируем каждую подсеть и добавляем её в поле №2
    for ip_bytes, prefix in cidrs:
        cidr_msg = b"\x0a" + encode_varint(len(ip_bytes)) + ip_bytes
        if prefix:  # В Protobuf нулевое значение (например, /0) можно опускать
            cidr_msg += b"\x10" + encode_varint(prefix)
        geoip_parts.append(b"\x12" + encode_varint(len(cidr_msg)) + cidr_msg)

    # Оборачиваем готовую категорию в элемент верхнего уровня (поле №1 файла geoip.dat)
    geoip_msg = b"".join(geoip_parts)
    return b"\x0a" + encode_varint(len(geoip_msg)) + geoip_msg


# =============================================================================
# БЛОК 4. Скачивание IPv4-списков из репозитория 123jjck/cdn-ip-ranges
# =============================================================================

def fetch_cdn_ipv4(name: str) -> set[tuple[bytes, int]]:
    """
    Скачивает текстовый файл <name>_plain_ipv4.txt из папки <name> репозитория cdn-ip-ranges
    и превращает строки вида '1.1.1.0/24' в множество пар (байты_IP, маска).
    """
    url = f"{CDN_REPO_RAW}/{name}/{name}_plain_ipv4.txt"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            text = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Не удалось скачать список '{name}' ({url}): HTTP {e.code}") from e

    cidrs: set[tuple[bytes, int]] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Пропускаем пустые строки и комментарии, начинающиеся с #
        if not line or line.startswith("#"):
            continue
        net = ipaddress.ip_network(line, strict=False)
        # Дополнительная страховка: берём строго IPv4
        if net.version == 4:
            cidrs.add((net.network_address.packed, net.prefixlen))

    if not cidrs:
        raise RuntimeError(f"Список '{name}' не содержит валидных IPv4-подсетей")
    return cidrs


# =============================================================================
# БЛОК 5. Сохранение файлов и главная точка входа
# =============================================================================

def write_dat_and_index(out_dir: Path, kind: str, entries: dict[str, bytes]) -> None:
    """
    Записывает на диск:
      1) Итоговый бинарный файл (geosite.dat или geoip.dat)
      2) Текстовый файл со списком всех категорий, которые попали внутрь (*-categories.txt)
    """
    if not entries:
        # Защита: если что-то пошло не так и файл оказался пустым, прерываем работу с ошибкой,
        # чтобы не затереть рабочие файлы в релизе пустышкой.
        raise RuntimeError(f"Итоговый {kind}.dat пуст — проверьте categories.json")

    dat_path = out_dir / f"{kind}.dat"
    txt_path = out_dir / f"{kind}-categories.txt"

    # Сортируем категории по алфавиту для порядка
    ordered_codes = sorted(entries.keys())
    # Склеиваем байты всех выбранных категорий в один файл
    dat_path.write_bytes(b"".join(entries[c] for c in ordered_codes))
    # Сохраняем список категорий в нижнем регистре (по одной на строку)
    txt_path.write_text("\n".join(f"{kind}:{c.lower()}" for c in ordered_codes) + "\n", encoding="utf-8")

    print(
        f"[{kind}.dat] Категорий: {len(ordered_codes)}, "
        f"размер: {dat_path.stat().st_size // 1024} KB -> {txt_path.name}"
    )


def main() -> None:
    """
    Главная функция. Запускается из командной строки так:
    python3 scripts/filter_dat.py categories.json tmp_src dist
      - sys.argv[1]: путь к файлу конфигурации (categories.json)
      - sys.argv[2]: папка со скачанными исходниками (tmp_src)
      - sys.argv[3]: папка, куда сохранить готовый результат (dist)
    """
    config_path = Path(sys.argv[1])
    src_dir = Path(sys.argv[2])
    out_dir = Path(sys.argv[3])
    # Создаём выходную папку, если её ещё нет
    out_dir.mkdir(parents=True, exist_ok=True)

    # Загружаем настройки из categories.json
    config = json.loads(config_path.read_text(encoding="utf-8"))

    # --- Шаг 1: Обработка Geosite ---
    # Приводим имена категорий к верхнему регистру и убираем случайные пробелы
    geosite_allowed = {c.strip().upper() for c in config.get("geosite", []) if c.strip()}
    geosite_entries = extract_entries(src_dir / "geosite.dat", geosite_allowed)
    write_dat_and_index(out_dir, "geosite", geosite_entries)

    # --- Шаг 2: Обработка GeoIP (исходник runetfreedom + IPv4 из cdn-ip-ranges) ---
    geoip_allowed = {c.strip().upper() for c in config.get("geoip", []) if c.strip()}
    raw_geoip_entries = extract_entries(src_dir / "geoip.dat", geoip_allowed)

    # Распаковываем бинарные категории GeoIP в множества подсетей, чтобы с ними можно было работать
    geoip_cidrs: dict[str, set[tuple[bytes, int]]] = {
        code: extract_cidrs_from_entry(chunk) for code, chunk in raw_geoip_entries.items()
    }

    # Скачиваем и добавляем списки из cdn-ip-ranges
    cdn_lists = [c.strip() for c in config.get("cdn_ip_ranges", []) if c.strip()]
    for name in cdn_lists:
        code = name.upper()
        cdn_cidrs = fetch_cdn_ipv4(name)
        if code in geoip_cidrs:
            # Если такая категория уже была в geoip.dat — объединяем (оператор |=)
            before = len(geoip_cidrs[code])
            geoip_cidrs[code] |= cdn_cidrs
            print(
                f"[cdn-ip-ranges] Категория '{name}' объединена с geoip.dat "
                f"({before} + {len(cdn_cidrs)} -> {len(geoip_cidrs[code])} до агрегации)"
            )
        else:
            # Иначе создаём новую категорию с таким же именем, как папка в репозитории
            geoip_cidrs[code] = cdn_cidrs
            print(f"[cdn-ip-ranges] Загружена категория '{name}' ({len(cdn_cidrs)} IPv4-подсетей)")

    # --- Шаг 3: Агрегация (схлопывание) IPv4-подсетей и сборка итогового geoip.dat ---
    geoip_entries: dict[str, bytes] = {}
    for code in sorted(geoip_cidrs.keys()):
        raw_set = geoip_cidrs[code]
        collapsed = collapse_ipv4_cidrs(raw_set)
        geoip_entries[code] = build_geoip_entry(code, collapsed)
        print(f"[geoip:{code.lower()}] Агрегация: {len(raw_set)} -> {len(collapsed)} подсетей")

    write_dat_and_index(out_dir, "geoip", geoip_entries)


# Стандартная конструкция Python: запускать main() только если файл запущен напрямую,
# а не импортирован в другой скрипт.
if __name__ == "__main__":
    main()
