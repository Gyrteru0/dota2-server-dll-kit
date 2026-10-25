# -*- coding: utf-8 -*-
"""
build_data.py — ПОЛНАЯ пересборка всех данных набора из server.dll.

Создаёт в ../data:
  pe_info.json             заголовки, секции, каталоги, экспорт, импорт, PDB, подпись
  exports.ndjson           6 точек входа модуля (CreateInterface, InstallSchemaBindings, ...)
  imports.ndjson           744 импорта из 7 DLL; для декорированных имён MSVC есть
                           поле "demangled" (разобранное имя, классы, соглашение о вызове)
  functions.tsv            ВСЕ функции из .pdata (244 974 шт.): id, границы, размер
  symbols.ndjson           все строки .rdata/.data = "символы" (адрес, RVA, секция, текст)
  rtti_types.txt           чистый список имён C++ типов из RTTI
  rtti_vtables.tsv         vtable_rva -> класс
  index_categorized.txt    строки по 15 категориям (RTTI, cvar, ассеты, ошибки, форматные...)
  function_strings.ndjson  КАКИЕ строки использует каждая функция  (главный файл)
  function_classes.ndjson  функция -> её C++ класс(ы) по RTTI
  string_functions.ndjson  обратный индекс: строка -> функции, которые на неё ссылаются

С --full дополнительно в ../data/extras:
  strings_full.txt         дамп ВСЕХ строк образа, включая .text (62 МБ)
  functions.ndjson         таблица функций в NDJSON (числа без 0x)
  function_strings.tsv     плоская таблица "функция - строка"
  symbols.tsv              строки-символы в TSV

Использование:
  python3 tools/build_data.py [--dll путь/к/server.dll] [--data путь/к/data] [--no-xref]

Зависимости: только стандартная библиотека Python + numpy (для xref).
numpy нужен ТОЛЬКО для --xref; остальное работает без него.
"""
import sys, os, json, re, struct, argparse, collections, datetime, math, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _pelib import PE, iter_strings, find_dll

RE_IDENT   = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
RE_FUNC    = re.compile(r'^[A-Z]{1,3}[A-Za-z0-9]*_[A-Za-z0-9_]+$')
RE_METHOD  = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*::[A-Za-z0-9_~]+$')
RE_CLASS   = re.compile(r'^C(DOTA|Source|Base|Engine|Game|World|Entity|Model|Schema|Valve|Panorama|Physics|Anim|Particle|Nav|VGUI|AI_|Point|Trigger|Env|Item|Unit|Player|Server|Client|Host|VScript|Pulse|Render|Sound|Light|Prop)[A-Za-z0-9_]*$')
RE_CVAR    = re.compile(r'^(sv|mp|dota|cl|host|r|phys|net|fps|tv|lobby|bot|debug|engine|game|anim|particle|vscript|pulse|client|server|ai|nav|snd|voice|mat|render|schema|ent|map|logic|npc|weapon|ability|item|health|mana|gold|xp|creep|tower|roshan|match|team|player|_)[a-z0-9]*(_[a-z0-9]+)+$')
RE_ATTR    = re.compile(r'^m_[A-Za-z0-9_]+$')
RE_CATTR   = re.compile(r'^CAttr_[A-Za-z0-9_@]+$')
RE_RTTI    = re.compile(r'^\.\?[AUVWT][A-Za-z0-9_@$?]{3,220}$')
RE_PROTO   = re.compile(r'\.proto$|^[A-Z][A-Za-z0-9]*(Msg|Message|Request|Response|Info|Data|Notification|Event|Result)$')
RE_ASSET   = re.compile(r'^[\w/\.\-]+\.(vmdl|vmat|vjs|vcss|vpk|vsnd|vsndevts|vpcf|vanim|vmesh|vphys|vmap|vwrld|vtxt|vxml|vdf|vcd|vcdlist|kv|kv3|txt|json|xml|png|tga|vtf|res|lst|cfg|ini|bin|nut|lua)$', re.I)
RE_PATH    = re.compile(r'^[\w\-\.]+[/\\][\w\-\.\/\\ ]+$')
RE_FMT     = re.compile(r'%[-+ #0]*[\d*]*(?:\.\d+)?(?:hh|h|ll|l|L|z|j|t)?[diouxXeEfgGaAcspn%]')
RE_MSG     = re.compile(r'(?:Failed|Error|Warning|Assert|Invalid|Unable|Cannot|Could not|Missing|Unknown|Unexpected|Attempted|Refusing|Ignoring|Unsupported|Deprecated|\bmust\b|\bshould\b)', re.I)
RE_SNAKE   = re.compile(r'^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$')
RE_DOTA    = re.compile(r'(dota|hero|ability|item|creep|tower|rune|courier|roshan|barracks|neutral|team_|player_|match|lobby|game_?mode|draft|radiant|dire|modifier|npc_)', re.I)
CPP_KW = {'__cdecl','__stdcall','__fastcall','__clrcall','__eabi','__ptr64','__restrict','__vectorcall',
          '__int8','__int16','__int32','__int64','__int128','__unaligned','__declspec','__forceinline',
          '__inline','__asm','__based','__multiple_inheritance','__virtual_inheritance','__thiscall',
          '__w64','__try','__except','__finally','__uuidof','__leave','__sealed','__event'}

# ---------------------------------------------------------------------------
# Упрощённый demangler декорированных имён MSVC (?...).
# Полную сигнатуру не восстанавливает, но reliably достаёт главное:
# имя сущности + классы, к которым она относится, + доступ/соглашение о вызовах.
# ---------------------------------------------------------------------------
SPECIAL_NAME = {'0': 'конструктор', '1': 'деструктор', '2': 'operator=', '3': 'operator<<',
                '4': 'operator>>', '5': 'operator!', '6': 'operator~', '7': 'operator!=',
                '8': 'operator==', '9': 'operator[]'}
FUNC_ACCESS = {'A': ('private', 'virtual __cdecl'), 'B': ('private', '__cdecl'),
               'C': ('private', '__cdecl'), 'D': ('private', '__thiscall'),
               'E': ('private', '__thiscall'), 'F': ('private', '__thiscall'),
               'G': ('private', '__thiscall'), 'H': ('private', '__cdecl'),
               'I': ('protected', 'virtual __cdecl'), 'J': ('protected', '__cdecl'),
               'K': ('protected', '__cdecl'), 'L': ('protected', '__thiscall'),
               'M': ('protected', '__thiscall'), 'N': ('protected', '__thiscall'),
               'O': ('protected', '__thiscall'), 'P': ('protected', '__cdecl'),
               'Q': ('public', 'virtual __cdecl'), 'R': ('public', '__cdecl'),
               'S': ('public', '__cdecl'), 'T': ('public', '__thiscall'),
               'U': ('public', '__thiscall'), 'V': ('public', '__thiscall'),
               'W': ('public', '__thiscall'), 'X': ('public', '__cdecl'),
               'Y': ('', '__cdecl'), 'Z': ('', '__cdecl'),
               '$$R': ('', '__cdecl'), '$$S': ('', '__cdecl'),
               '$$Q': ('public', '__ptr64 __cdecl'), '$$T': ('public', '__ptr64 __thiscall'),
               '$$A': ('private', '__cdecl'), '$$B': ('private', '__cdecl'),
               '$$C': ('private', '__cdecl'), '$$F': ('private', '__thiscall'),
               '$$G': ('private', '__thiscall'), '$$J': ('protected', '__cdecl'),
               '$$K': ('protected', '__cdecl'), '$$U': ('public', '__thiscall'),
               '$$V': ('public', '__thiscall')}
SIMPLE_TYPE = {'X': 'void', 'D': 'char', 'E': 'unsigned char', 'F': 'short',
               'G': 'unsigned short', 'H': 'int', 'I': 'unsigned int', 'J': 'long',
               'K': 'unsigned long', 'M': 'float', 'N': 'double', 'O': 'long double',
               '_J': '__int64', '_K': 'unsigned __int64', '_L': '__int128',
               'PEBD': 'const char*', 'PEAD': 'char*', 'PEBV': 'const class&',
               'PEAX': 'void*', '_N': 'bool'}


def demangle_msvc(name):
    """Разобрать декорированное имя MSVC (упрощённо, но надёжно по сути).

    Возвращает dict: raw, demangled, entity, classes, kind, access, calling_convention,
    is_static, is_const, note.
    Полная сигнатура (типы аргументов) не восстанавливается — для поиска
    «что делает функция» достаточно имени метода и его классов.
    """
    out = {'raw': name, 'demangled': name, 'entity': name, 'classes': [], 'kind': 'c',
           'access': None, 'calling_convention': None, 'is_static': False,
           'is_const': False, 'note': ''}
    if not name.startswith('?'):
        out['note'] = 'не декорированное имя (C linkage)'
        return out
    b = name[1:]

    # --- 1) шаблон: ?$Name@Params@@ ---
    if b.startswith('$'):
        b = b[1:]
        at = b.find('@@')
        head = b[:at] if at > 0 else b
        parts = [p for p in head.split('@') if p]
        ent = parts[0] if parts else name
        params = []
        for prm in parts[1:]:
            m = re.match(r'^[VUW](.+?)$', prm)
            params.append(m.group(1) if m else prm)
        out.update(kind='template', entity=ent, classes=params,
                   demangled=f'{ent}<{", ".join(params)}>')
        return out

    # --- 2) специальные имена: ??0 ctor, ??1 dtor, ??2 operator new ... ---
    special = None
    if b.startswith('?'):
        c = b[1:2]
        special = SPECIAL_NAME.get(c)
        b = b[2:]
        if special is None:
            special = '?' + c
    # --- 3) двухсимвольные коды доступа $$Q/$$T/... ---
    two = None
    if b.startswith('$$'):
        two = '$$' + b[2:3]
        b = b[3:]

    at = b.find('@@')
    qual = b[:at] if at > 0 else b
    tail = b[at + 2:] if at > 0 else ''
    parts = [p for p in qual.split('@') if p]
    if not parts:
        out.update(kind='other', note='не разобрано')
        return out

    entity = special or parts[0]
    # у шаблонов первый компонент может начинаться с префикса типа (V/U/W): V?$CUtlVector -> ?$CUtlVector
    if not special and len(entity) > 2 and entity[0] in 'VUW' and entity[1] in '?CUI':
        entity = entity[1:]
    rest = parts[1:]
    acc = two
    if not acc and rest and re.fullmatch(r'[A-Z]', rest[-1]):
        acc = rest[-1]; rest = rest[:-1]
    elif not acc and not two and rest and re.fullmatch(r'[A-Z]', rest[-1] if rest else ''):
        pass
    # код доступа может идти и первым символом tail (у простых имён ?Name@Class@@QEAA...)
    if not acc and tail and re.fullmatch(r'[A-Z]', tail[0]):
        acc = tail[0]; tail = tail[1:]
    classes = list(reversed(rest))
    access, conv = FUNC_ACCESS.get(acc, (None, None)) if acc else (None, None)
    is_static = bool(acc and acc in '0123456789')
    ret = ''
    if tail and not special:
        m = re.match(r'^\^?A?([A-Z_]{1,4})', tail)
        if m:
            ret = SIMPLE_TYPE.get(m.group(1), '')
    dem = '::'.join(classes + [entity]) if classes else entity
    out.update(kind=('constructor' if special == 'конструктор' else
                     'destructor' if special == 'деструктор' else 'function'),
               entity=entity, classes=classes, demangled=dem,
               access=access, calling_convention=conv, is_static=is_static,
               note=' '.join(x for x in (access, conv, (f'-> {ret}' if ret else '')) if x))
    return out


CATS = [
 ('A. RTTI — имена C++ типов (классы/структуры/перечисления)',       lambda s: RE_RTTI.match(s)),
 ('B. Сетевые атрибуты схемы данных (CAttr_m_*)',                    lambda s: RE_CATTR.match(s)),
 ('C. Поля данных классов (m_*)',                                    lambda s: RE_ATTR.match(s)),
 ('D. Имена методов (Class::Method)',                                lambda s: RE_METHOD.match(s)),
 ('E. Имена функций/констант в стиле Valve (PREFIX_Name)',           lambda s: RE_FUNC.match(s)),
 ('F. Имена классов движка и игры (CDOTA*, CSource*, CBase*...)',    lambda s: RE_CLASS.match(s)),
 ('G. Protobuf: .proto-файлы и типы сообщений',                      lambda s: RE_PROTO.match(s)),
 ('H. Игровые ассеты и файлы (модели, материалы, звуки, скрипты)',   lambda s: RE_ASSET.match(s)),
 ('I. Консольные переменные и команды (cvar / concommand)',          lambda s: RE_CVAR.match(s)),
 ('J. Сообщения об ошибках, предупреждениях и ассертах',             lambda s: RE_MSG.search(s)),
 ('K. Форматные строки (видно, какие аргументы у функции)',          lambda s: RE_FMT.search(s)),
 ('L. Dota-идентификаторы (герои, способности, предметы, режимы)',   lambda s: RE_DOTA.search(s) and RE_SNAKE.match(s)),
 ('M. Пути',                                                         lambda s: RE_PATH.match(s)),
 ('N. Прочие идентификаторы',                                        lambda s: RE_IDENT.match(s) and len(s) >= 6 and not s.isupper()),
 ('O. Человеко-читаемые тексты, описания, подсказки',                lambda s: ' ' in s and len(s) >= 12 and re.search(r'[a-z]{3}', s)),
]

def entropy(b):
    if not b: return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def build_pe_info(pe):
    d = pe.data
    info = {
      'file': os.path.basename(pe.path),
      'size_bytes': pe.size,
      'sha256': pe.sha256(),
      'md5': pe.md5(),
      'pe_type': 'PE32+' if pe.pe32plus else 'PE32',
      'machine': f'0x{pe.machine:x}',
      'machine_name': 'AMD64' if pe.machine == 0x8664 else ('I386' if pe.machine == 0x14c else '?'),
      'num_sections': pe.nsec,
      'timestamp': pe.timestamp,
      'timestamp_utc': datetime.datetime.fromtimestamp(pe.timestamp, datetime.timezone.utc).isoformat(),
      'image_base': f'0x{pe.image_base:x}',
      'entry_point_rva': f'0x{pe.entry_rva:x}',
      'entry_point_va': f'0x{pe.rva2va(pe.entry_rva):x}',
      'subsystem': pe.subsystem,
      'characteristics': f'0x{pe.chars:x}',
      'dll_characteristics': f'0x{pe.dll_chars:x}',
      'sections': [],
      'data_directories': [],
      'pdb': None,
      'authenticode': None,
    }
    for s in pe.sections:
        b = d[s.raw:s.raw + min(s.rawsize, 8 << 20)]
        info['sections'].append({
          'name': s.name, 'virtual_address': f'0x{s.va:x}', 'virtual_size': s.vsize,
          'raw_offset': f'0x{s.raw:x}', 'raw_size': s.rawsize,
          'characteristics': f'0x{s.chars:x}', 'entropy': round(entropy(b), 3),
          'in_file_only_bytes': min(s.vsize, s.rawsize),
          'bss_bytes': max(0, s.vsize - s.rawsize),
        })
    for n in ('EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC','DEBUG',
              'TLS','LOAD_CONFIG','IAT','DELAY_IMPORT','CLR_RUNTIME'):
        rva, sz = pe.dirs[n]
        if not (rva or sz): continue
        info['data_directories'].append({
          'name': n, 'rva': f'0x{rva:x}', 'size': sz,
          'present_in_file': pe.rva2off(rva) is not None,
          'file_offset': (f'0x{pe.rva2off(rva):x}' if pe.rva2off(rva) is not None else None)})
    p = pe.pdb_info()
    if p: info['pdb'] = {'path': p[0], 'guid': p[1], 'age': p[2]}

    # ---------- ЭКСПОРТЫ ----------
    exp = pe.exports()
    if exp:
        info['exports'] = {'dll_name': exp['name'], 'ordinal_base': exp['ordinal_base'],
                           'num_functions': exp['num_functions'], 'num_names': exp['num_names'],
                           'entries': [{'ordinal': o, 'name': n, 'rva': f'0x{r:x}',
                                        'va': f'0x{pe.rva2va(r):x}', 'forwarder': fw}
                                       for o, n, r, fw in exp['entries']]}

    # ---------- ИМПОРТЫ ----------
    imp = pe.imports()
    if imp is not None:
        info['imports'] = {'num_dlls': len(imp['dlls']),
                           'num_functions': sum(x['num_functions'] for x in imp['dlls']),
                           'dlls': [{'name': x['name'], 'num_functions': x['num_functions'],
                                     'iat_rva': f"0x{x['iat_rva']:x}",
                                     'functions': x['functions']} for x in imp['dlls']]}
    else:
        info['imports'] = None
    rva, sz = pe.dirs['SECURITY']
    if 0 < rva < pe.size:
        sig = d[rva:rva + sz]
        raw = sorted(set(x.decode('latin1') for x in re.findall(rb'[\x20-\x7e]{8,120}', sig)))
        # DER-обёртки добавляют перед текстом байт длины (цифру/символ) — отфильтровываем мусор
        names = []
        for x in raw:
            x = x.lstrip('0123456789')
            if len(x) < 6: continue
            if not re.search(r'[A-Za-z]{3}', x): continue
            if re.fullmatch(r'[0-9A-Za-z+/=]{16,}', x): continue
            names.append(x)
        info['authenticode'] = {'file_offset': f'0x{rva:x}', 'size': sz,
                                'readable_fragments': names[:80]}
    return info

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dll'); ap.add_argument('--data')
    ap.add_argument('--no-xref', action='store_true')
    ap.add_argument('--full', action='store_true',
                    help='дополнительно собрать extras/ (strings_full.txt 62 МБ, CSV/TSV-дубликаты)')
    ap.add_argument('--min-len', type=int, default=4)
    a = ap.parse_args()
    dll = find_dll(a.dll)
    if not os.path.isfile(dll):
        print(f'НЕ НАЙДЕН ФАЙЛ: {dll}\nПоложите server.dll рядом с папкой tools/ '
              f'или укажите --dll /путь/к/server.dll'); return 2
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data = a.data or os.path.join(root, 'data')
    os.makedirs(data, exist_ok=True)
    def P(n): return os.path.join(data, n)
    print(f'[*] {dll} ({os.path.getsize(dll)} байт)')
    pe = PE(dll)

    # ---------- pe_info ----------
    info = build_pe_info(pe)
    json.dump(info, open(P('pe_info.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(f'[+] {os.path.relpath(data, os.getcwd())}/pe_info.json')

    # ---------- imports / exports ----------
    if info.get('imports'):
        with open(P('imports.ndjson'), 'w', encoding='utf-8', newline='\n') as f:
            for dl in info['imports']['dlls']:
                for fn in dl['functions']:
                    nm = fn.get('name')
                    rec = {'dll': dl['name'], 'name': nm, 'ordinal': fn.get('ordinal'),
                           'hint': fn.get('hint')}
                    if nm and nm.startswith('?'):
                        rec['demangled'] = demangle_msvc(nm)
                    f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        print(f'[+] {os.path.relpath(data, os.getcwd())}/imports.ndjson  '
              f'({info["imports"]["num_functions"]} импортируемых функций из '
              f'{info["imports"]["num_dlls"]} DLL)')
    if info.get('exports'):
        with open(P('exports.ndjson'), 'w', encoding='utf-8', newline='\n') as f:
            for e in info['exports']['entries']:
                f.write(json.dumps({'ordinal': e['ordinal'], 'name': e['name'],
                                    'rva': e['rva'], 'va': e['va'],
                                    'forwarder': e['forwarder']}, ensure_ascii=False) + '\n')
        print(f'[+] {os.path.relpath(data, os.getcwd())}/exports.ndjson  '
              f'({info["exports"]["num_names"]} экспортов)')

    # ---------- functions ----------
    fns = pe.functions()
    # TSV: три числа на функцию -> в 2 раза компактнее NDJSON и быстрее читается
    with open(P('functions.tsv'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('id\tbegin_rva\tend_rva\tsize\tbegin_va\tend_va\tunwind_rva\n')
        for i, (b, e, u) in enumerate(fns):
            f.write(f'{i}\t0x{b:08x}\t0x{e:08x}\t{e-b}\t0x{pe.rva2va(b):x}\t'
                    f'0x{pe.rva2va(e):x}\t0x{u:08x}\n')
    print(f'[+] {os.path.relpath(data, os.getcwd())}/functions.tsv  ({len(fns)} функций)')
    if a.full:
        os.makedirs(os.path.join(data, 'extras'), exist_ok=True)
        with open(P('extras/functions.ndjson'), 'w', encoding='utf-8', newline='\n') as f:
            for i, (b, e, u) in enumerate(fns):
                f.write(json.dumps({'id': i, 'begin_rva': b, 'end_rva': e, 'size': e - b,
                                    'begin_va': pe.rva2va(b), 'end_va': pe.rva2va(e),
                                    'unwind_rva': u}, ensure_ascii=False) + '\n')
        print(f'[+] {os.path.relpath(data, os.getcwd())}/extras/functions.ndjson')

    # ---------- symbols (строки в .rdata/.data) ----------
    syms = []
    for off, rva, secn, kind, txt in iter_strings(pe, min_len=a.min_len, sections={'.rdata', '.data'}):
        if txt in CPP_KW: continue
        syms.append((off, rva, secn, kind, txt))
    with open(P('symbols.ndjson'), 'w', encoding='utf-8', newline='\n') as f:
        for off, rva, secn, kind, txt in syms:
            f.write(json.dumps({'off': f'0x{off:08x}', 'rva': f'0x{rva:08x}', 'va': pe.rva2va(rva),
                                'section': secn, 'kind': kind, 'len': len(txt), 'text': txt},
                               ensure_ascii=False) + '\n')
    with open(P('extras/symbols.tsv') if a.full else os.devnull, 'w', encoding='utf-8', newline='\n') as f:
        f.write('off\trva\tva\tsection\tkind\tlen\ttext\n')
        for off, rva, secn, kind, txt in syms:
            f.write(f'0x{off:08x}\t0x{rva:08x}\t0x{pe.rva2va(rva):x}\t{secn}\t{kind}\t{len(txt)}\t{txt}\n')
    print(f'[+] {os.path.relpath(data, os.getcwd())}/symbols.ndjson  ({len(syms)} строк-символов)' + (', extras/symbols.tsv' if a.full else ''))

    # ---------- strings_full (extras, только --full) ----------
    n_all = 0
    if a.full:
        os.makedirs(os.path.join(data, 'extras'), exist_ok=True)
    with open(P('extras/strings_full.txt') if a.full else os.devnull, 'w', encoding='utf-8', newline='\n') as f:
        f.write('# ПОЛНЫЙ ДАМП СТРОК ОБРАЗА\n')
        f.write(f'# файл={os.path.basename(dll)} размер={pe.size} sha256={info["sha256"]}\n')
        f.write('# формат: 0x<file_off>  RVA=0x<rva>  VA=0x<va>  <section>  <kind>  len=<n>  |<текст>|\n')
        for off, rva, secn, kind, txt in iter_strings(pe, min_len=a.min_len):
            f.write(f'0x{off:08x}  RVA=0x{rva:08x}  VA=0x{pe.rva2va(rva):x}  {secn:8} {kind:5} '
                    f'len={len(txt):6}  |{txt.replace(chr(9), chr(92)+"t")}|\n')
            n_all += 1
    if a.full: print(f'[+] {os.path.relpath(data, os.getcwd())}/extras/strings_full.txt  ({n_all} строк)')

    # ---------- index_categorized + rtti ----------
    seen = collections.defaultdict(list)
    for off, rva, secn, kind, txt in syms:
        seen[txt].append((off, rva))
    buckets = collections.OrderedDict((n, []) for n, _ in CATS)
    rtti = []
    for txt, occ in seen.items():
        if txt in CPP_KW: continue
        for name, test in CATS:
            if test(txt):
                buckets[name].append(txt)
                if name.startswith('A.'): rtti.append(txt)
                break
    with open(P('index_categorized.txt'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('=' * 120 + '\n# ИНДЕКС ОСМЫСЛЕННЫХ СТРОК (секции .rdata/.data)\n')
        f.write(f'# файл={os.path.basename(dll)} sha256={info["sha256"]}\n')
        f.write('# формат:  <строка> @ 0x<file_off>, ...  [кол-во вхождений]\n' + '=' * 120 + '\n\n')
        f.write('СОДЕРЖАНИЕ:\n')
        for k in buckets: f.write(f'  {k:95} {len(buckets[k]):>7}\n')
        f.write('\n')
        for k in buckets:
            f.write('#' * 120 + f'\n# {k}   —   всего {len(buckets[k])}\n' + '#' * 120 + '\n')
            for t in sorted(buckets[k], key=lambda x: (x.lower(), x)):
                occ = seen[t]
                f.write(t + ' @ ' + ', '.join(f'0x{o:08x}' for o, _ in occ[:4])
                        + (' …' if len(occ) > 4 else '') + f'   [{len(occ)}]\n')
            f.write('\n')
    with open(P('rtti_types.txt'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted(set(rtti))) + '\n')
    print(f'[+] {os.path.relpath(data, os.getcwd())}/index_categorized.txt, rtti_types.txt')

    # ---------- xref: строка -> код -> функция ----------
    if a.no_xref:
        print('[!] xref пропущен (--no-xref)')
        return 0
    try:
        import numpy as np
    except ImportError:
        print('[!] numpy не установлен — xref пропущен. Установите: pip install numpy'); return 0
    xref_strings_to_functions(pe, syms, fns, P, full=a.full, data=data)
    return 0

def disasm_rip_refs(pe, fns, progress=True):
    """Дизассемблирует каждую функцию (границы из .pdata) и собирает ВСЕ RIP-относительные
    обращения к памяти. Возвращает список (function_index, code_rva, target_rva)."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone import x86 as cx86
    d = pe.data
    ib = pe.image_base
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    sec = pe.sections
    def raw(rva):
        for s in sec:
            if s.va <= rva < s.va + max(s.vsize, s.rawsize):
                o = s.raw + (rva - s.va)
                if 0 <= o < len(d): return o
        return None
    out = []
    t0 = time.time()
    for i, (b, e, u) in enumerate(fns):
        o = raw(b)
        if o is None or e <= b: continue
        code = d[o:o + (e - b)]
        for insn in md.disasm(code, ib + b):
            try: ops = insn.operands
            except Exception: continue
            if not ops: continue
            op = ops[-1]
            if op.type == cx86.X86_OP_MEM and op.mem.base == cx86.X86_REG_RIP:
                out.append((i, insn.address - ib, insn.address + insn.size + op.mem.disp - ib))
        if progress and i and i % 40000 == 0:
            print(f'    ... {i}/{len(fns)} функций, {len(out)} RIP-ссылок, {time.time()-t0:.0f}с')
    if progress:
        print(f'[*] дизассемблирование: {len(out)} RIP-ссылок за {time.time()-t0:.0f}с')
    return out


def rtti_class_map(pe):
    """Восстанавливает соответствие vtable -> имя C++ класса по RTTI (x64).

    x64 RTTI: vtable[-1] = VA(CompleteObjectLocator);
    COL: sig(4)=1, offset(4), cdOffset(4), pTypeDescriptor RVA(4), pClassHierarchy RVA(4), pSelf RVA(4);
    TypeDescriptor: pVFTable(8), spare(8), имя (.?AVClass@@) как строка.
    """
    import numpy as np
    d = pe.data
    ib = pe.image_base
    size = len(d)
    # 1) TypeDescriptor'ы: ищем в .rdata 16-байтные заголовки, за которыми идёт ".?A"
    tds = {}          # rva(TD) -> имя класса
    td_by_name = {}
    for s in pe.sections:
        if s.name not in ('.rdata', '.data'): continue
        blob = d[s.raw:s.raw + s.rawsize]
        for m in re.finditer(rb'\.\?[AUVWT][A-Za-z0-9_@$?]{3,220}\x00', blob):
            name_off = s.raw + m.start()
            td_rva = s.va + (name_off - 16 - s.raw)
            if td_rva < 0: continue
            tds[td_rva] = m.group()[:-1].decode('latin1')
            td_by_name.setdefault(m.group()[:-1].decode('latin1'), []).append(td_rva)
    # 2) COL'ы: 4-байтное поле pTypeDescriptor указывает на TD
    td_arr = np.fromiter(tds.keys(), dtype=np.uint32, count=len(tds))
    cols = {}         # rva(COL) -> имя
    for s in pe.sections:
        if s.name not in ('.rdata', '.data'): continue
        blob = np.frombuffer(d[s.raw:s.raw + s.rawsize - (s.rawsize % 4)], dtype='<u4')
        base_rva = s.va
        idx = np.flatnonzero(np.isin(blob, td_arr))
        for j in idx.tolist():
            fld_rva = base_rva + j * 4
            col_rva = fld_rva - 12          # pTypeDescriptor — 4-е поле (sig,offset,cdOffset,TD)
            if col_rva < base_rva: continue
            sig = int.from_bytes(d[s.raw + (col_rva - base_rva):s.raw + (col_rva - base_rva) + 4], 'little')
            if sig != 1: continue
            td_rva = int.from_bytes(d[s.raw + (fld_rva - base_rva):s.raw + (fld_rva - base_rva) + 4], 'little')
            cols[col_rva] = tds[td_rva]
    # 3) vtables: ищем 8-байтные значения VA(COL) в .rdata/.data -> vtable = pos+8
    vtables = {}      # rva(vtable) -> имя
    if cols:
        col_va = np.array([ib + c for c in cols], dtype=np.uint64)
        col_keys = list(cols)
        for s in pe.sections:
            if s.name not in ('.rdata', '.data'): continue
            n = (s.rawsize // 8) * 8
            blob = np.frombuffer(d[s.raw:s.raw + n], dtype='<u8')
            idx = np.flatnonzero(np.isin(blob, col_va))
            for j in idx.tolist():
                pos_rva = s.va + j * 8
                vt_rva = pos_rva + 8
                # определить имя по значению VA
                va = int(blob[j])
                colr = va - ib
                nm = cols.get(colr)
                if nm: vtables[vt_rva] = nm
    return tds, cols, vtables, td_by_name


def xref_strings_to_functions(pe, syms, fns, P, full=False, data='data'):
    """Главный проход: строка -> код -> функция + класс функции по RTTI."""
    import numpy as np
    d = pe.data
    # символы: RVA -> (off, section, kind, text)
    tgt = {}
    for off, rva, secn, kind, txt in syms:
        if rva: tgt.setdefault(rva, []).append((off, secn, kind, txt))
    try:
        refs = disasm_rip_refs(pe, fns)
    except ImportError:
        print('[!] capstone не установлен — xref невозможен. Установите: pip install capstone')
        return
    print('[*] строю карту RTTI-классов...')
    tds, cols, vtables, td_by_name = rtti_class_map(pe)
    print(f'[*] RTTI: TypeDescriptor={len(tds)}, COL={len(cols)}, vtable={len(vtables)}')
    # классы, на которые ссылается каждая функция (по vtable/COL)
    fn_classes = collections.defaultdict(collections.Counter)
    fn_refs_str = collections.defaultdict(list)
    fn_stats = collections.defaultdict(lambda: [0, 0, 0])   # code, rdata, data
    sec_of_rva = {}
    for s in pe.sections:
        sec_of_rva[s.name] = (s.va, s.va + max(s.vsize, s.rawsize))
    def secname(rva):
        for nm, (a, b) in sec_of_rva.items():
            if a <= rva < b: return nm
        return '-'
    for i, code_rva, t in refs:
        sn = secname(t)
        st = fn_stats[i]
        if sn == '.text': st[0] += 1
        elif sn == '.rdata': st[1] += 1
        elif sn == '.data': st[2] += 1
        if t in tgt:
            for off, secn, kind, txt in tgt[t]:
                fn_refs_str[i].append((code_rva, t, off, secn, kind, txt))
        if t in vtables:
            fn_classes[i][vtables[t]] += 1
        elif t in cols:
            fn_classes[i][cols[t]] += 1
    print(f'[*] функций со ссылками на строки: {len(fn_refs_str)}; '
          f'с определённым классом: {len(fn_classes)}')

    with open(P('function_strings.ndjson'), 'w', encoding='utf-8', newline='\n') as f:
        for i in sorted(set(fn_refs_str) | set(fn_classes)):
            b, e, u = fns[i]
            refs_i = sorted(set(fn_refs_str.get(i, [])))
            cls = [c for c, _ in fn_classes.get(i, collections.Counter()).most_common()]
            st = fn_stats[i]
            f.write(json.dumps({
                'function_id': i,
                'begin_rva': f'0x{b:08x}', 'end_rva': f'0x{e:08x}', 'size': e - b,
                'begin_va': pe.rva2va(b), 'end_va': pe.rva2va(e),
                'classes': cls,
                'refs_code': st[0], 'refs_rdata': st[1], 'refs_data': st[2],
                'num_strings': len(refs_i),
                'strings': [{'code_rva': f'0x{cr:08x}', 'target_rva': f'0x{tr:08x}',
                             'file_off': f'0x{so:08x}', 'section': sn, 'kind': kd, 'text': tx}
                            for cr, tr, so, sn, kd, tx in refs_i]}, ensure_ascii=False) + '\n')
    if full:
        os.makedirs(os.path.dirname(P('extras/function_strings.tsv')), exist_ok=True)
        with open(P('extras/function_strings.tsv'), 'w', encoding='utf-8', newline='\n') as f:
            f.write('function_id\tbegin_rva\tend_rva\tsize\tclasses\tcode_rva\ttarget_rva\tfile_off\tsection\tkind\tstring\n')
            for i in sorted(fn_refs_str):
                b, e, u = fns[i]
                cls = ','.join(c for c, _ in fn_classes.get(i, collections.Counter()).most_common())
                for cr, tr, so, sn, kd, tx in sorted(set(fn_refs_str[i])):
                    f.write(f'{i}\t0x{b:08x}\t0x{e:08x}\t{e-b}\t{cls}\t0x{cr:08x}\t0x{tr:08x}\t'
                            f'0x{so:08x}\t{sn}\t{kd}\t{tx}\n')
    fn_by_str = collections.defaultdict(set)
    str_loc = {}                                    # текст -> (target_rva, file_off)
    for i, lst in fn_refs_str.items():
        for cr, tr, so, sn, kd, tx in lst:
            fn_by_str[tx].add(i)
            str_loc.setdefault(tx, (tr, so))
    with open(P('string_functions.ndjson'), 'w', encoding='utf-8', newline='\n') as f:
        for txt in sorted(fn_by_str):
            ids = sorted(fn_by_str[txt])
            tr, so = str_loc[txt]
            f.write(json.dumps({'text': txt, 'target_rva': f'0x{tr:08x}', 'target_off': so,
                                'num_functions': len(ids),
                                'functions': [{'id': i, 'begin_rva': f'0x{fns[i][0]:08x}',
                                               'end_rva': f'0x{fns[i][1]:08x}',
                                               'begin_va': pe.rva2va(fns[i][0]),
                                               'size': fns[i][1] - fns[i][0]} for i in ids[:128]]},
                               ensure_ascii=False) + '\n')
    with open(P('function_classes.ndjson'), 'w', encoding='utf-8', newline='\n') as f:
        for i in sorted(fn_classes):
            b, e, u = fns[i]
            f.write(json.dumps({'function_id': i, 'begin_rva': f'0x{b:08x}', 'end_rva': f'0x{e:08x}',
                                'size': e - b, 'begin_va': pe.rva2va(b),
                                'classes': [{'name': c, 'weight': w}
                                            for c, w in fn_classes[i].most_common()]},
                               ensure_ascii=False) + '\n')
    with open(P('rtti_vtables.tsv'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('vtable_rva\tclass\n')
        for v in sorted(vtables): f.write(f'0x{v:08x}\t{vtables[v]}\n')
    print(f'[+] {os.path.relpath(data, os.getcwd())}/function_strings.ndjson  ({len(fn_refs_str)} функций)')
    if full: print(f'[+] {os.path.relpath(data, os.getcwd())}/extras/function_strings.tsv')
    print(f'[+] {os.path.relpath(data, os.getcwd())}/string_functions.ndjson  ({len(fn_by_str)} строк)')
    print(f'[+] {os.path.relpath(data, os.getcwd())}/function_classes.ndjson  ({len(fn_classes)} функций с классом)')
    print(f'[+] {os.path.relpath(data, os.getcwd())}/rtti_vtables.tsv  ({len(vtables)} vtable -> класс)')

if __name__ == '__main__':
    sys.exit(main())
