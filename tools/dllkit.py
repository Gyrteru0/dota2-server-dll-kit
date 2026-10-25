#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dllkit.py — единый CLI для анализа server.dll (Dota 2 / Source 2) по готовым данным.

Работает БЕЗ самого .dll, если есть папка data/ (дизассемблирование требует server.dll).

Команды:
  find      <подстрока|/regex/>          поиск по всем строкам-символам и именам классов
  func      <rva|va|0x…|id>              всё о функции: класс, строки, статистика ссылок
  who-uses  <строка|rva|смещение>        какие функции ссылаются на строку
  near      <file_off|rva> [--window N]  соседние строки (контекст модуля)
  bytes     <rva|off> [--size N]         hex-дамп + дизассемблирование (нужен server.dll)
  pe                                     заголовки, секции, PDB, подпись
  classes   <подстрока>                  C++ классы из RTTI + их vtable и функции
  demangle  [<имена>...]                 разобрать декорированные имена MSVC (?Class@Method@@...)
  cvars     [подстрока]                  консольные переменные/команды
  stats                                    сводка по набору данных

Глобальные флаги: --json (машинный вывод), --limit N, --data ПУТЬ, --dll ПУТЬ.
Работают и ДО, и ПОСЛЕ имени команды: `dllkit.py --limit 20 find x` == `dllkit.py find x --limit 20`.

Код выхода: 0 — успех, 1 — ничего не найдено, 2 — нужен сам server.dll (команда `bytes`).

Примеры:
  python3 tools/dllkit.py find "Roshan"
  python3 tools/dllkit.py who-uses "Error parsing lua modifier from string table!" --json
  python3 tools/dllkit.py who-uses 0x03b81f28              # то же по RVA строки
  python3 tools/dllkit.py func 0x00bf03fd
  python3 tools/dllkit.py near 0x03b80528 --off --window 20
  python3 tools/dllkit.py classes CDOTA_Ability
  python3 tools/dllkit.py demangle "?LoadFromFile@KeyValues@@QEAA_NPEBDW4PathType_t@@@Z"
  python3 tools/dllkit.py bytes 0x00bf03fd --size 128      # нужен server.dll
"""
import os, sys, json, re, argparse, bisect, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)


def data_dir(a):
    return a.data or os.environ.get('DLLKIT_DATA') or os.path.join(ROOT, 'data')


def ndjson(path):
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def load_index(dd, name):
    p = os.path.join(dd, '_index', name)
    if os.path.isfile(p):
        return json.load(open(p, encoding='utf-8'))
    return None


def get_record(dd, fname, key):
    """Точечное чтение одной записи NDJSON по ключу через _index (seek, без полного скана)."""
    idx = load_index(dd, fname.replace('.ndjson', '.idx.json'))
    if not idx:
        return None
    off = idx.get(key if isinstance(key, str) else str(key))
    if isinstance(off, list):      # мультисловный индекс: берём первое вхождение
        off = off[0] if off else None
    if off is None:
        return None
    with open(os.path.join(dd, fname), 'r', encoding='utf-8') as f:
        f.seek(off)
        line = f.readline()
    try:
        return json.loads(line)
    except Exception:
        return None


def to_int(x):
    if isinstance(x, int):
        return x
    x = x.strip().replace('_', '')
    return int(x, 16) if x.lower().startswith('0x') else int(x, 0)


# --------------------------------------------------------------------------- find
def cmd_find(a):
    dd = data_dir(a)
    pat = a.pattern
    regex = re.compile(pat[1:-1], re.I) if len(pat) > 2 and pat.startswith('/') and pat.endswith('/') \
        else re.compile(re.escape(pat), re.I)
    res = []
    src = os.path.join(dd, 'symbols.ndjson')
    for rec in ndjson(src):
        t = rec['text']
        if regex.search(t):
            res.append({'kind': 'string', 'text': t, 'file_off': rec['off'], 'rva': rec['rva'],
                        'va': hex(rec['va']) if isinstance(rec['va'], int) else rec['va'],
                        'section': rec['section'], 'encoding': rec['kind'], 'len': rec['len']})
            if len(res) >= a.limit:
                break
    if a.json:
        print(json.dumps({'pattern': pat, 'count': len(res), 'results': res}, ensure_ascii=False, indent=1))
        return 0
    print(f'Поиск «{pat}» в data/symbols.ndjson — найдено {len(res)} (лимит {a.limit})')
    print(f'{"file_off":>12} {"rva":>12} {"секция":8} {"тип":6} текст')
    for r in res:
        print(f'{r["file_off"]:>12} {r["rva"]:>12} {r["section"]:8} {r["encoding"]:6} {r["text"][:150]}')
    print('\nДальше: python3 tools/dllkit.py who-uses "<текст>"   — кто использует эту строку')
    return 0


# --------------------------------------------------------------------------- who-uses
def rva_to_off(dd, rva):
    """RVA -> смещение в файле по таблице секций из data/pe_info.json. None, если вне секций."""
    info = json.load(open(os.path.join(dd, 'pe_info.json'), encoding='utf-8'))
    for sec in info['sections']:
        va = int(sec['virtual_address'], 16)
        vs = sec['virtual_size']
        if va <= rva < va + vs:
            return int(sec['raw_offset'], 16) + (rva - va)
    return None


def cmd_who_uses(a):
    dd = data_dir(a)
    target = a.string
    exact = get_record(dd, 'string_functions.ndjson', target)
    note = None
    if not exact and (target.lower().startswith('0x') or target.isdigit()):
        # Допускаем RVA (индекс string_functions.ndjson построен по file_off)
        try:
            val = int(target, 16) if target.lower().startswith('0x') else int(target, 10)
        except ValueError:
            val = None
        if val is not None:
            off = val if target.isdigit() else rva_to_off(dd, val)
            rva = val if not target.isdigit() else None
            if off is not None:
                idx2 = load_index(dd, 'string_functions_byoff.idx.json')
                o2 = (idx2 or {}).get(str(off))
                if isinstance(o2, list) and o2:
                    with open(os.path.join(dd, 'string_functions.ndjson'), encoding='utf-8') as fh:
                        fh.seek(o2[0]); exact = json.loads(fh.readline())
                if exact:
                    note = (f'RVA {target} -> смещение в файле {off} (0x{off:x})' if rva is not None
                        else f'смещение в файле {off} (0x{off:x})')
    hits = []
    if exact:
        hits = [exact]
    else:
        rx = re.compile(re.escape(target), re.I) if not (target.startswith('/') and target.endswith('/')) \
            else re.compile(target[1:-1], re.I)
        for rec in ndjson(os.path.join(dd, 'string_functions.ndjson')):
            if rx.search(rec['text']):
                hits.append(rec)
                if len(hits) >= a.limit:
                    break
    out = []
    for h in hits[:a.limit]:
        funcs = []
        for f in h['functions'][:a.functions]:
            fr = get_record(dd, 'function_strings.ndjson', f['id'])
            funcs.append({'function_id': f['id'], 'begin_rva': f['begin_rva'], 'end_rva': f['end_rva'],
                          'size': f['size'], 'begin_va': f.get('begin_va'),
                          'classes': (fr or {}).get('classes', []),
                          'num_strings': (fr or {}).get('num_strings', 0)})
        out.append({'string': h['text'], 'num_functions': h['num_functions'], 'functions': funcs})
    if a.json:
        print(json.dumps({'query': target, 'matches': len(out), 'results': out}, ensure_ascii=False, indent=1))
        return 0
    if not out:
        print(f'Строка «{target}» не найдена среди строк, на которые ссылается код.')
        print('Попробуйте: python3 tools/dllkit.py find "<часть строки>"')
        return 1
    if note:
        print(note)
    for o in out:
        print(f'СТРОКА: {o["string"]}')
        print(f'  ссылаются функций: {o["num_functions"]}')
        for f in o['functions']:
            cls = ', '.join(f['classes']) or '—'
            print(f'  #{f["function_id"]:<7} RVA {f["begin_rva"]}–{f["end_rva"]} '
                  f'({f["size"]} байт)  класс: {cls}')
            print(f'           подробно: python3 tools/dllkit.py func {f["begin_rva"]}')
        print()
    return 0


# --------------------------------------------------------------------------- func
def load_functions_starts(dd):
    """Границы всех функций. Источник: data/functions.tsv (id, begin_rva, end_rva, size, ...).

    Возвращает (starts, ends, ids) — три параллельных списка, отсортированных по begin_rva.
    Кэшируется в data/_index/_functions_starts.json (в git не коммитится).
    """
    cache = os.path.join(dd, '_index', '_functions_starts.json')
    if os.path.isfile(cache):
        try:
            a = json.load(open(cache))
            if a.get('version') == 2:
                return a['starts'], a['ends'], a['ids']
        except Exception:
            pass
    tsv = os.path.join(dd, 'functions.tsv')
    if not os.path.isfile(tsv):
        raise SystemExit(f'НЕ НАЙДЕН {tsv}\nПересоберите данные: python3 tools/build_data.py --dll <путь>')
    starts, ends, ids = [], [], []
    with open(tsv, encoding='utf-8') as f:
        next(f, None)                              # заголовок
        for line in f:
            p = line.split('\t')
            if len(p) < 4:
                continue
            ids.append(int(p[0]))
            starts.append(int(p[1], 16))
            ends.append(int(p[2], 16))
    try:
        os.makedirs(os.path.dirname(cache), exist_ok=True)
        json.dump({'version': 2, 'starts': starts, 'ends': ends, 'ids': ids}, open(cache, 'w'))
    except Exception:
        pass
    return starts, ends, ids


def cmd_func(a):
    dd = data_dir(a)
    starts, ends, ids = load_functions_starts(dd)
    pe_info = json.load(open(os.path.join(dd, 'pe_info.json'), encoding='utf-8'))
    ib = int(pe_info['image_base'], 16)
    q = a.addr
    if q.startswith('id:'):
        fid = int(q[3:]); i = fid
        b, e = starts[i], ends[i]
    else:
        v = to_int(q)
        rva = v - ib if v >= ib else v
        i = bisect.bisect_right(starts, rva) - 1
        if i < 0:
            print('Адрес до первой функции'); return 1
        b, e = starts[i], ends[i]
        if not (b <= rva < e):
            print(f'RVA 0x{rva:08x} не попадает в функцию (ближайшая начинается 0x{b:08x}, '
                  f'заканчивается 0x{e:08x}) — возможно, это данные или промежуток')
    fid = ids[i] if i < len(ids) else i
    rec = get_record(dd, 'function_strings.ndjson', fid)
    cls = get_record(dd, 'function_classes.ndjson', fid)
    out = {
        'function_id': fid,
        'begin_rva': f'0x{b:08x}', 'end_rva': f'0x{e:08x}', 'size': e - b,
        'begin_va': ib + b, 'end_va': ib + e,
        'classes': (cls or {}).get('classes', []) or (rec or {}).get('classes', []),
        'refs_code': (rec or {}).get('refs_code'), 'refs_rdata': (rec or {}).get('refs_rdata'),
        'refs_data': (rec or {}).get('refs_data'),
        'strings': (rec or {}).get('strings', []),
        'commands': {
            'disasm': f'python3 tools/dllkit.py bytes 0x{b:08x} --size {min(e-b, 4096)}',
            'who_uses_each_string': 'python3 tools/dllkit.py who-uses "<текст строки>"',
        },
    }
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=1)); return 0
    print(f'ФУНКЦИЯ #{fid}')
    print(f'  RVA      : 0x{b:08x} – 0x{e:08x}   ({e-b} байт)')
    print(f'  VA       : 0x{ib+b:x} – 0x{ib+e:x}   (ImageBase 0x{ib:x})')
    if out['classes']:
        print(f'  КЛАСС    : {", ".join(c["name"] if isinstance(c, dict) else c for c in out["classes"])}')
    else:
        print('  КЛАСС    : не определён (функция не грузит vtable/RTTI — свободная функция или шаблон)')
    if rec:
        print(f'  ссылки   : в код {rec["refs_code"]}, в .rdata {rec["refs_rdata"]}, в .data {rec["refs_data"]}')
        print(f'  СТРОКИ, которые использует функция ({rec["num_strings"]}):')
        for s in rec['strings'][:a.strings]:
            print(f'    0x{s["code_rva"][2:]:>8} -> [{s["section"]} {s["kind"]}] {s["text"][:160]}')
        if rec['num_strings'] > a.strings:
            print(f'    ... ещё {rec["num_strings"]-a.strings} (увеличьте --strings)')
    else:
        print('  СТРОКИ   : функция не ссылается ни на одну строку (типично для мелких геттеров/математики)')
    print(f'\n  дизассемблирование: python3 tools/dllkit.py bytes 0x{b:08x} --size {min(e-b,4096)}')
    return 0


# --------------------------------------------------------------------------- near
def cmd_near(a):
    dd = data_dir(a)
    v = to_int(a.addr)
    pe_info = json.load(open(os.path.join(dd, 'pe_info.json'), encoding='utf-8'))
    ib = int(pe_info['image_base'], 16)
    # --rva -> True, --off -> False, без флага -> None (эвристика: RVA, если v < ImageBase)
    is_rva = a.rva if a.rva is not None else (v < ib)
    rows = []
    for rec in ndjson(os.path.join(dd, 'symbols.ndjson')):
        rows.append((int(rec['off'], 16), rec))
    rows.sort()
    offs = [r[0] for r in rows]
    if is_rva:
        # ищем по RVA
        rows = sorted(((int(r['rva'], 16), r) for _, r in rows))
        offs = [r[0] for r in rows]
        pos = bisect.bisect_left(offs, v)
    else:
        pos = bisect.bisect_left(offs, v)
    w = min(a.window, max(1, (a.limit + 1) // 2)) if a.limit else a.window
    lo = max(0, pos - w); hi = min(len(rows), pos + w + 1)
    out = []
    for k in range(lo, hi):
        key, rec = rows[k]
        out.append({'file_off': rec['off'], 'rva': rec['rva'], 'section': rec['section'],
                    'kind': rec['kind'], 'len': rec['len'], 'text': rec['text']})
    if a.json:
        print(json.dumps({'anchor': hex(v), 'window': a.window, 'results': out}, ensure_ascii=False, indent=1))
        return 0
    print(f'Соседние строки вокруг {"RVA" if is_rva else "file_off"} 0x{v:x} (±{w}):')
    for i, r in enumerate(out):
        mark = '>>>' if i == pos - lo else '   '
        print(f'{mark} {r["file_off"]:>12} {r["rva"]:>12} {r["section"]:8} {r["text"][:150]}')
    return 0


# --------------------------------------------------------------------------- bytes
def cmd_bytes(a):
    dd = data_dir(a)
    from _pelib import PE, find_dll
    dll = find_dll(a.dll)
    if not os.path.isfile(dll):
        print(f'Нужен сам файл DLL для hex/дизассемблирования: не найден «{dll}».\n'
              f'Укажите --dll /путь/к/server.dll (или скачайте: python3 tools/get_dll.py)')
        return 2
    pe = PE(dll)
    v = to_int(a.addr)
    if v >= pe.image_base:
        rva = v - pe.image_base
    elif a.off:
        rva = pe.off2rva(v)
        if rva is None:
            print('Смещение вне секций файла'); return 1
    else:
        rva = v
    off = pe.rva2off(rva)
    if off is None:
        print(f'RVA 0x{rva:08x} не присутствует в файле (BSS)'); return 1
    blob = pe.data[off:off + a.size]
    if a.json:
        print(json.dumps({'rva': f'0x{rva:08x}', 'va': f'0x{pe.rva2va(rva):x}', 'file_off': f'0x{off:08x}',
                          'size': len(blob), 'hex': blob.hex()}, ensure_ascii=False, indent=1))
        return 0
    print(f'RVA 0x{rva:08x}  VA 0x{pe.rva2va(rva):x}  file_off 0x{off:08x}  {len(blob)} байт')
    print('-' * 78)
    for i in range(0, len(blob), 16):
        ch = blob[i:i + 16]
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch)
        print(f'0x{rva+i:08x}  {ch.hex(" "):<47}  |{asc}|')
    if not a.no_disasm:
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        except ImportError:
            print('\n(capstone не установлен — дизассемблирование пропущено: pip install capstone)')
            return 0
        s = pe.section_of_rva(rva)
        if s and s.name == '.text':
            print('-' * 78)
            md = Cs(CS_ARCH_X86, CS_MODE_64); md.skipdata = True
            n = 0
            for insn in md.disasm(blob, pe.rva2va(rva)):
                print(f'0x{insn.address-pe.image_base:08x}  {insn.bytes.hex(" "):<24} {insn.mnemonic:<10} {insn.op_str}')
                n += 1
                if n >= a.insns:
                    break
        else:
            print(f'\n(0x{rva:08x} находится в {s.name if s else "?"} — не код, дизассемблирование пропущено)')
    return 0


# --------------------------------------------------------------------------- pe
def cmd_pe(a):
    dd = data_dir(a)
    info = json.load(open(os.path.join(dd, 'pe_info.json'), encoding='utf-8'))
    if a.json:
        print(json.dumps(info, ensure_ascii=False, indent=1)); return 0
    print(f'{info["file"]}  {info["size_bytes"]} байт  {info["pe_type"]} {info["machine_name"]}')
    print(f'  SHA-256 : {info["sha256"]}')
    print(f'  MD5     : {info["md5"]}')
    print(f'  сборка  : {info["timestamp_utc"]}   ImageBase {info["image_base"]}   EntryPoint {info["entry_point_rva"]}')
    if info.get('pdb'):
        print(f'  PDB     : {info["pdb"]["path"]}')
        print(f'  GUID    : {info["pdb"]["guid"]}  age={info["pdb"]["age"]}')
    print('\n  СЕКЦИИ')
    print(f'    {"имя":10} {"VA":>10} {"VSize":>10} {"RawOff":>10} {"RawSize":>10} {"энтропия":>9}  BSS')
    for s in info['sections']:
        print(f'    {s["name"]:10} {s["virtual_address"]:>10} {s["virtual_size"]:>10} '
              f'{s["raw_offset"]:>10} {s["raw_size"]:>10} {s["entropy"]:>9}  {s["bss_bytes"]}')
    print('\n  КАТАЛОГИ ДАННЫХ')
    for x in info['data_directories']:
        print(f'    {x["name"]:14} RVA {x["rva"]:>10}  размер {x["size"]:>9}  '
              f'в файле: {"да" if x["present_in_file"] else "НЕТ (BSS)"}')
    if info.get('exports'):
        e = info['exports']
        print(f'\n  ЭКСПОРТЫ ({e["num_names"]} имён, ordinal base {e["ordinal_base"]}, '
              f'внутреннее имя DLL «{e["dll_name"]}»):')
        for x in e['entries']:
            print(f'    [{x["ordinal"]}] {x["name"]:28} RVA {x["rva"]}  VA {x["va"]}')
        print('    Это точка входа для движка: CreateInterface отдаёт фабрику интерфейсов')
        print('    серверного модуля, InstallSchemaBindings подключает схему данных сущностей.')
    if info.get('imports'):
        im = info['imports']
        print(f'\n  ИМПОРТЫ ({im["num_dlls"]} DLL, {im["num_functions"]} функций):')
        for dl in im['dlls']:
            print(f'    {dl["name"]:18} {dl["num_functions"]:>4} функций')
        print('    Полный список: data/imports.ndjson (для tier0.dll имена декорированы')
        print('    по правилам MSVC — там же поле demangled с разобранным именем).')
    if info.get('authenticode'):
        print('\n  ПОДПИСЬ (Authenticode), читаемые фрагменты:')
        for x in info['authenticode']['readable_fragments'][:25]:
            if len(x) > 4:
                print('    ' + x[:110])
    return 0


# --------------------------------------------------------------------------- demangle
def cmd_demangle(a):
    try:
        from build_data import demangle_msvc
    except ImportError:
        sys.path.insert(0, HERE)
        from build_data import demangle_msvc
    names = a.names
    if not names:
        dd = data_dir(a)
        p = os.path.join(dd, 'imports.ndjson')
        out = []
        for rec in ndjson(p):
            if (rec.get('name') or '').startswith('?'):
                out.append({'dll': rec['dll'], 'raw': rec['name'],
                            **(rec.get('demangled') or demangle_msvc(rec['name']))})
        if a.json:
            print(json.dumps({'count': len(out), 'results': out}, ensure_ascii=False, indent=1))
            return 0
        print(f'Декорированные имена из data/imports.ndjson: {len(out)}')
        for o in out[:a.limit]:
            print(f'  [{o["dll"]:12}] {o["demangled"][:80]:82} | {o.get("note","")}')
        if len(out) > a.limit:
            print(f'  ... ещё {len(out)-a.limit} (увеличьте --limit или добавьте --json)')
        return 0
    res = [demangle_msvc(n) for n in names]
    if a.json:
        print(json.dumps({'results': res}, ensure_ascii=False, indent=1)); return 0
    for r in res:
        print(f'{r["raw"]}')
        print(f'   -> {r["demangled"]}')
        print(f'      классы: {r["classes"] or "—"}   вид: {r["kind"]}   {r["note"]}')
    return 0


# --------------------------------------------------------------------------- classes
def cmd_classes(a):
    dd = data_dir(a)
    rx = re.compile(a.pattern, re.I) if not (a.pattern.startswith('/') and a.pattern.endswith('/')) \
        else re.compile(a.pattern[1:-1], re.I)
    hits = []
    for line in open(os.path.join(dd, 'rtti_types.txt'), encoding='utf-8'):
        t = line.strip()
        if t and rx.search(t):
            hits.append(t)
            if len(hits) >= a.limit:
                break
    vt = {}
    p = os.path.join(dd, 'rtti_vtables.tsv')
    if os.path.isfile(p):
        for i, line in enumerate(open(p, encoding='utf-8')):
            if i == 0:
                continue
            parts = line.rstrip('\n').split('\t')
            if len(parts) == 2:
                vt.setdefault(parts[1], []).append(parts[0])
    if a.json:
        print(json.dumps({'pattern': a.pattern, 'count': len(hits),
                          'classes': [{'name': h, 'vtables': vt.get(h, [])} for h in hits]},
                         ensure_ascii=False, indent=1))
        return 0
    print(f'Классы по маске «{a.pattern}»: {len(hits)}')
    for h in hits:
        vs = vt.get(h, [])
        print(f'  {h}   vtable: {", ".join(vs) if vs else "—"}')
    print('\nНайти функции класса:  python3 tools/dllkit.py find "<имя класса>"')
    print('                       python3 tools/dllkit.py who-uses "<имя класса>"')
    return 0


# --------------------------------------------------------------------------- cvars
def cmd_cvars(a):
    dd = data_dir(a)
    rx = re.compile(re.escape(a.pattern), re.I) if a.pattern else None
    out = []
    for rec in ndjson(os.path.join(dd, 'symbols.ndjson')):
        t = rec['text']
        if not re.match(r'^[a-z_][a-z0-9_]*$', t) or '_' not in t:
            continue
        if rx and not rx.search(t):
            continue
        out.append({'name': t, 'file_off': rec['off'], 'rva': rec['rva'], 'section': rec['section']})
        if len(out) >= a.limit:
            break
    if a.json:
        print(json.dumps({'count': len(out), 'cvars': out}, ensure_ascii=False, indent=1)); return 0
    print(f'Похоже на cvar/concommand: {len(out)} (лимит {a.limit})')
    for o in out:
        print(f'  {o["name"]:60} {o["file_off"]} {o["rva"]} {o["section"]}')
    print('\nКто использует:  python3 tools/dllkit.py who-uses "<имя>"')
    return 0


# --------------------------------------------------------------------------- stats
def cmd_stats(a):
    dd = data_dir(a)
    man = os.path.join(dd, '_index.json')
    rows = []
    if os.path.isfile(man):
        m = json.load(open(man, encoding='utf-8'))
        for fn, e in m['files'].items():
            rows.append((fn, e['size_bytes'], e.get('records')))
    known = {r[0] for r in rows}
    for fn in sorted(os.listdir(dd)):
        p = os.path.join(dd, fn)
        if not os.path.isfile(p) or fn in known:
            continue
        n = None
        if fn.endswith(('.tsv', '.txt')):
            with open(p, encoding='utf-8', errors='replace') as fh:
                n = sum(1 for _ in fh) - (1 if fn.endswith('.tsv') else 0)
        rows.append((fn, os.path.getsize(p), n))
    rows.sort(key=lambda r: r[0])
    nfun = next((r[2] for r in rows if r[0] == 'functions.tsv'), None)
    if a.json:
        print(json.dumps({'data_dir': dd, 'files': [{'name': r[0], 'size': r[1], 'records': r[2]} for r in rows]},
                         ensure_ascii=False, indent=1)); return 0
    info = json.load(open(os.path.join(dd, 'pe_info.json'), encoding='utf-8'))
    print(f'Набор данных: {dd}')
    print(f'  источник : {info["file"]}  {info["size_bytes"]} байт  sha256={info["sha256"][:16]}…')
    print(f'  функций  : {nfun if nfun is not None else "?"}  (data/functions.tsv)')
    print('\n  %-32s %12s %10s' % ('файл','размер','записей'))
    for fn, sz, rec in rows:
        print(f'  {fn:32} {sz:>12} {rec if rec is not None else "-":>10}')
    return 0


class SharedSubParsersAction(argparse._SubParsersAction):
    """Подкоманды разбирают аргументы В ТОМ ЖЕ namespace, что и основной парсер.

    Стандартный argparse создаёт для подкоманды свежий Namespace и затем копирует
    его значения поверх уже разобранных — из-за этого глобальные флаги, указанные
    ДО имени команды (`dllkit.py --limit 6 find x`), молча сбрасывались на дефолт.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        parser_name = values[0]
        arg_strings = values[1:]
        if self.dest is not argparse.SUPPRESS:
            setattr(namespace, self.dest, parser_name)
        try:
            parser = self._name_parser_map[parser_name]
        except KeyError:
            self._check_value(None, parser_name)
            raise
        res = parser.parse_known_args(arg_strings, namespace)
        # Python 3.13+: parse_known_args возвращает (namespace, extras),
        # раньше — (extras, namespace). Обрабатываем оба варианта.
        if isinstance(res[0], argparse.Namespace):
            _, extras = res
        else:
            extras, _ = res
        if extras:
            setattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR,
                    getattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR, []) + list(extras))


class NamesAction(argparse.Action):
    """Список имён для `demangle`, который не проглатывает следующие за ним флаги."""

    def __call__(self, parser, ns, values, option_string=None):
        for i, v in enumerate(values):
            if v.startswith('-') and not v.startswith('?'):
                rest = values[i:]
                values = values[:i]
                break
        else:
            rest = []
        setattr(ns, self.dest, values)
        return rest


def main():
    ap = argparse.ArgumentParser(prog='dllkit.py', description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--data', help='папка data/ (по умолчанию ../data)')
    ap.add_argument('--dll', help='путь к server.dll (нужен только для `bytes`)')
    ap.add_argument('--json', action='store_true', help='вывод в JSON (для машин/ИИ-агентов)')
    ap.add_argument('--limit', type=int, default=60, help='максимум строк в выдаче')
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--data', help=argparse.SUPPRESS)
    common.add_argument('--dll', help=argparse.SUPPRESS)
    common.add_argument('--json', action='store_true', help=argparse.SUPPRESS)
    common.add_argument('--limit', type=int, default=60, help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest='cmd', required=True, action=SharedSubParsersAction)

    def sp(name, help_, **kw):
        return sub.add_parser(name, help=help_, parents=[common], **kw)

    p = sp('find', 'поиск строк/символов'); p.add_argument('pattern'); p.set_defaults(f=cmd_find)
    p = sp('who-uses', 'какие функции ссылаются на строку (текст, RVA или смещение)')
    p.add_argument('string'); p.add_argument('--functions', type=int, default=20); p.set_defaults(f=cmd_who_uses)
    p = sp('func', 'всё о функции по RVA/VA/id')
    p.add_argument('addr'); p.add_argument('--strings', type=int, default=60); p.set_defaults(f=cmd_func)
    p = sp('near', 'соседние строки вокруг адреса')
    p.add_argument('addr'); p.add_argument('--window', type=int, default=40)
    p.add_argument('--rva', action='store_true', default=None,
                   help='адрес — это RVA (по умолчанию определяется эвристикой)')
    p.add_argument('--off', action='store_false', dest='rva',
                   help='адрес — это смещение в файле')
    p.set_defaults(f=cmd_near)
    p = sp('bytes', 'hex + дизассемблирование (нужен сам server.dll)')
    p.add_argument('addr'); p.add_argument('--size', type=int, default=256)
    p.add_argument('--insns', type=int, default=200); p.add_argument('--off', action='store_true')
    p.add_argument('--no-disasm', action='store_true'); p.set_defaults(f=cmd_bytes)
    p = sp('pe', 'PE-структура: секции, каталоги, экспорт, импорт, подпись'); p.set_defaults(f=cmd_pe)
    p = sp('classes', 'C++ классы из RTTI'); p.add_argument('pattern'); p.set_defaults(f=cmd_classes)
    p = sp('cvars', 'консольные переменные/команды')
    p.add_argument('pattern', nargs='?', default=''); p.set_defaults(f=cmd_cvars)
    p = sp('demangle', 'разобрать декорированные имена MSVC (?...)',
           description='Имена можно перечислять в любом количестве; глобальные флаги '
                       '(--limit/--json/--data) работают и до, и после имени команды.')
    p.add_argument('names', nargs='*', action=NamesAction,
                   help='имена; без аргументов — все из data/imports.ndjson')
    p.set_defaults(f=cmd_demangle)
    p = sp('stats', 'сводка по набору данных'); p.set_defaults(f=cmd_stats)

    a = ap.parse_args()
    return a.f(a)


if __name__ == '__main__':
    sys.exit(main())
