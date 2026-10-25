# DATA_FORMATS.md — точное описание файлов в `data/`

Все файлы — UTF-8, окончания строк LF. Машинные форматы: **NDJSON** (один JSON-объект
на строку, читается потоково) и **TSV/CSV** (для таблиц). Человекочитаемые: **TXT/MD**.

Адреса везде в трёх видах:

| Вид | Что это | Пример |
|---|---|---|
| `file_off` | байтовая позиция в файле `server.dll` | `0x0305d188` |
| `rva` | Relative Virtual Address (смещение от начала образа в памяти) | `0x0305eb88` |
| `va` | Virtual Address = `rva + ImageBase`, ImageBase = `0x180000000` | `6459489160` (десятичное) |

Пересчёт `rva ↔ file_off` по секциям (значения из `pe_info.json`):

| Секция | VA (rva) | Raw offset | Формула |
|---|---|---|---|
| `.text`   | `0x00001000` | `0x00000400` | `file_off = rva - 0xC00` |
| `.rdata`  | `0x02e6e000` | `0x02e6c600` | `file_off = rva - 0x1A00` |
| `.data`   | `0x048b2000` | `0x048b0400` | `file_off = rva - 0x1C00` |
| `.pdata`  | `0x053f4000` | `0x04cf9a00` | `file_off = rva - 0x6F6000` |
| `.reloc`  | `0x056c2000` | `0x04fc7600` | `file_off = rva - 0x6FAA00` |

---

## 1. `pe_info.json` — 84 КБ

Единственный JSON-объект (не NDJSON). Структура:

```jsonc
{
 "file": "server.dll",
 "size_bytes": 88194712,
 "sha256": "f7b7d300c9d32ddd07e9b211026288c8c017528938486414a0a01037981cc566",
 "md5": "6178027dd7ae966282cf36598e7e0408",
 "pe_type": "PE32+", "machine": "0x8664", "machine_name": "AMD64",
 "num_sections": 5,
 "timestamp": 1792859597, "timestamp_utc": "2026-10-24T16:33:17+00:00",
 "image_base": "0x180000000",
 "entry_point_rva": "0x2da21b8", "entry_point_va": "0x182da21b8",
 "subsystem": 2,                       // 2 = WINDOWS_CUI
 "characteristics": "0x2022", "dll_characteristics": "0x160",
 "sections": [
   {"name": ".text", "virtual_address": "0x1000", "virtual_size": 48677088,
    "raw_offset": "0x400", "raw_size": 48677376, "characteristics": "0x60000020",
    "entropy": 6.676, "in_file_only_bytes": 48677088, "bss_bytes": 0}
   // ... .rdata, .data, .pdata, .reloc
 ],
 "data_directories": [
   {"name": "EXPORT", "rva": "0x48aa370", "size": 244,
    "present_in_file": false, "file_offset": null}
   // present_in_file=false => RVA указывает в BSS-часть .data, в файле этих данных нет
 ],
 "pdb": {"path": "C:\\buildworker\\source2_dota_rel_2019_win64\\...\\Retail\\server.pdb",
         "guid": "698B48EE6F0A41BCAE586273770EE7BE", "age": 30},
 "authenticode": {"file_offset": "0x5419200", "size": 11416,
                  "readable_fragments": ["Valve Corp.", "DigiCert, Inc.", "..."]}
}
```

Поля `bss_bytes` важны: у `.data` `virtual_size` (11 803 900) больше `raw_size` (4 494 848) —
хвост это неинициализированные данные, которых в файле физически нет. Каталог `EXPORT`
(RVA `0x048AA370`) и `IMPORT` (RVA `0x048AA464`) при этом попадают в **файловую** часть
`.data` (она покрывает RVA до `0x04CF9A00`), поэтому обе таблицы читаются полностью —
см. `exports`/`imports` в этом же JSON и отдельные файлы ниже.

Внутри `pe_info.json` также есть:

```jsonc
"exports": {"dll_name": "server.dll", "ordinal_base": 1, "num_functions": 6, "num_names": 6,
  "entries": [{"ordinal": 2, "name": "CreateInterface", "rva": "0x2d85b70",
               "va": "0x182d85b70", "forwarder": false}]},
"imports": {"num_dlls": 7, "num_functions": 744,
  "dlls": [{"name": "tier0.dll", "num_functions": 554, "iat_rva": "0x48abd56",
            "functions": [{"ordinal": null, "name": "?FindKey@KeyValues@@QEAA...", "hint": 123}]}]}
```

---

## 1a. `exports.ndjson` — 654 Б, 6 записей

Точки входа, по которым движок Source 2 подключает модуль.

```jsonc
{"ordinal": 2, "name": "CreateInterface", "rva": "0x2d85b70",
 "va": "0x182d85b70", "forwarder": false}
```

| ordinal | name | RVA | зачем |
|---|---|---|---|
| 1 | `BinaryProperties_GetValue` | 0x01DCFE00 | бинарные свойства модуля |
| 2 | `CreateInterface` | 0x02D85B70 | фабрика интерфейсов (`IServerGameDLL`, `Source2Server`, …) |
| 3 | `ExtractModuleMetadata` | 0x01DD0580 | метаданные для системы ресурсов |
| 4 | `GetResourceManifestCount` | 0x02D9A2E0 | число манифестов ресурсов |
| 5 | `GetResourceManifests` | 0x02D9A2F0 | сами манифесты |
| 6 | `InstallSchemaBindings` | 0x02D9C2D0 | подключение схемы данных сущностей (поля `m_*`) |

`forwarder: true` означало бы, что экспорт перенаправлен в другую DLL — здесь таких нет.

---

## 1b. `imports.ndjson` — 169 КБ, 744 записи

По одной записи на импортируемую функцию.

```jsonc
{"dll": "USER32.dll", "name": "MessageBoxW", "ordinal": null, "hint": 650}
{"dll": "tier0.dll",
 "name": "?FindKey@KeyValues@@QEAAPEAVCKeyValues_Data@@PEBDH_N@Z",
 "ordinal": null, "hint": 41,
 "demangled": {"raw": "?FindKey@KeyValues@@QEAA...", "demangled": "KeyValues::FindKey",
               "entity": "FindKey", "classes": ["KeyValues"], "kind": "function",
               "access": "public", "calling_convention": "virtual __cdecl",
               "is_static": false, "is_const": false, "note": "public virtual __cdecl"}}
```

Поле `demangled` добавляется только для декорированных имён MSVC (начинаются с `?`) —
в этом файле таких **316** (все из `tier0.dll`). `ordinal` не null только для импорта
по порядковому номеру (здесь таких нет).

Разбор по DLL:

| DLL | Функций |
|---|---|
| `tier0.dll` | 554 |
| `KERNEL32.dll` | 121 |
| `GDI32.dll` | 22 |
| `USER32.dll` | 16 |
| `WS2_32.dll` | 15 |
| `steam_api64.dll` | 13 |
| `ADVAPI32.dll` | 3 |

---

## 2. `functions.tsv` — 15.6 МБ, 244 974 строки (+ заголовок)

Границы **всех** функций, восстановленные из каталога `EXCEPTION` (`.pdata`, массив
`RUNTIME_FUNCTION`). Это единственный надёжный источник границ функций в retail-бинарнике.

TSV с заголовком (табуляция, hex с `0x`):

```
id	begin_rva	end_rva	size	begin_va	end_va	unwind_rva
0	0x0000146d	0x00001531	196	0x18000146d	0x180001531	0x048664e0
1	0x00001a1d	0x00001ae8	203	0x180001a1d	0x180001ae8	0x048664f0
```

* `id` — порядковый номер (0…244973). Он же значение `function_id` во всех остальных файлах.
* `begin_rva`/`end_rva` — RVA начала и конца функции; `size` = разница, байт кода.
  Медиана 77 байт, максимум 54 954.
* `unwind_rva` — RVA структуры `UNWIND_INFO` (как раскручивать стек при исключении).
* Строки идут **строго по возрастанию `begin_rva`** → «какая функция содержит адрес X»
  решается бинарным поиском.

Загрузка и бинарный поиск (Python, без pandas):

```python
import bisect
starts, ends, ids = [], [], []
with open('data/functions.tsv', encoding='utf-8') as f:
    next(f)                                     # заголовок
    for line in f:
        p = line.split('\t')
        ids.append(int(p[0])); starts.append(int(p[1], 16)); ends.append(int(p[2], 16))

rva = 0x00bf044e
i = bisect.bisect_right(starts, rva) - 1
assert starts[i] <= rva < ends[i]
print('function_id', ids[i])                    # -> 54984
```

`tools/dllkit.py` делает то же самое и кэширует результат в
`data/_index/_functions_starts.json` (файл в git не коммитится, пересоздаётся автоматически).

NDJSON-вариант (`{"id":0,"begin_rva":4461,"end_rva":5425,...}`, числа без `0x`) создаётся
только при `build_data.py --full` и кладётся в `data/extras/functions.ndjson` — он в 2 раза
больше при той же информации, поэтому по умолчанию не собирается.

---

## 3. `symbols.ndjson` — 20 МБ, 128 361 записей

Все строки-символы из секций `.rdata` и `.data` (длина ≥ 4, ключевые слова C++ отброшены).
Это «словарь» бинарника: тексты логов и ошибок, cvar, имена полей схемы, имена Lua-методов,
пути ассетов, имена protobuf-типов.

```jsonc
{"off": "0x0305d188", "rva": "0x0305eb88", "va": 6459489160,
 "section": ".rdata", "kind": "ascii", "len": 44,
 "text": "Error parsing lua modifier from string table!"}
```

* `off`/`rva` — hex-строки, `va` — число;
* `kind`: `ascii` (однобайтовая) или `wide` (UTF-16LE);
* `len` — длина в символах;
* одна и та же строка может встречаться несколько раз — тогда это **разные записи**
  с разными `off`/`rva` (дубликаты строк в бинарнике реальны).

---

## 4. `function_strings.ndjson` — 41 МБ, 72 946 записей ★ главный файл

Профиль каждой функции, которая ссылается хотя бы на одну строку или vtable.

```jsonc
{"function_id": 54984,
 "begin_rva": "0x00bf03fd", "end_rva": "0x00bf09d0", "size": 1491,
 "begin_va": 6454969341, "end_va": 6454970832,
 "classes": [".?AVCDOTALuaModifierEntry@@"],
 "refs_code": 0, "refs_rdata": 27, "refs_data": 5,
 "num_strings": 7,
 "strings": [
   {"code_rva": "0x00bf044e", "target_rva": "0x0305eb88", "file_off": "0x0305d188",
    "section": ".rdata", "kind": "ascii",
    "text": "Error parsing lua modifier from string table!"}
 ]}
```

* `classes` — имена C++-классов по RTTI, отсортированы по весу (сколько раз функция
  обратилась к vtable/COL этого класса). Пустой список = класс не определён
  (свободная функция, шаблон, статическая функция или метод без обращения к vtable).
  Префиксы MSVC: `.?AV` = class, `.?AU` = struct, `.?AW` = enum, `.?AT` = union.
* `refs_code` / `refs_rdata` / `refs_data` — сколько RIP-относительных ссылок из этой
  функции ведут в `.text` (вызовы/переходы/таблицы), `.rdata` (константы, vtable, строки),
  `.data` (глобальные переменные). Полезный признак: `refs_data` > 0 означает, что функция
  читает/пишет глобальное состояние.
* `strings[].code_rva` — RVA **инструкции**, которая загружает строку. По нему можно
  дизассемблировать конкретное место: `dllkit.py bytes <code_rva>`.
* `num_strings` — длина `strings`.

Записи отсортированы по `function_id`. Ключ в `_index/function_strings.idx.json` — строка
`"54984"`.

---

## 5. `string_functions.ndjson` — 15 МБ, 51 932 записи

Обратный индекс: строка → функции, которые её загружают.

```jsonc
{"text": "roshan_gold", "target_rva": "0x02d09b60", "target_off": 47225696,
 "num_functions": 2,
 "functions": [{"id": 75886, "begin_rva": "0x00f297f0", "end_rva": "0x00f29813",
                "begin_va": 6451533808, "size": 35}]}
```

* `target_rva` / `target_off` — где именно в образе лежит эта строка (первое вхождение);

* `functions` — максимум первые 128 (отсортированы по `id`); `num_functions` — истинное
  количество, оно может быть больше;
* ключ в `_index/string_functions.idx.json` — **точный текст строки**;
  ключ в `_index/string_functions_byoff.idx.json` — **десятичное `target_off`**.
  Поэтому `dllkit.py who-uses` принимает и текст, и RVA (`0x03b81f28`), и смещение в файле
  (`62391592`) — RVA он сам переводит в смещение по таблице секций из `pe_info.json`.
  Если нужен поиск по подстроке, `who-uses` сканирует файл (или используйте grep).

Здесь только те строки, на которые код ссылается RIP-относительно (`lea reg,[rip+disp]` /
`mov reg,[rip+disp]`). Строка, лежащая в статической таблице (например, элемент массива
описателей cvar или protobuf-дескриптора), в этот файл **не попадёт** — её нужно искать
через `near` по соседству.

---

## 6. `function_classes.ndjson` — 4.6 МБ, 22 489 записей

Только сопоставление «функция → класс», без строк. Удобно, чтобы перечислить все методы класса.

```jsonc
{"function_id": 54984, "begin_rva": "0x00bf03fd", "end_rva": "0x00bf09d0",
 "size": 1491, "begin_va": 6454969341,
 "classes": [{"name": ".?AVCDOTALuaModifierEntry@@", "weight": 1}]}
```

`weight` — сколько RIP-ссылок функции ведут на vtable/COL этого класса. При нескольких
кандидатах список отсортирован по убыванию веса; первый элемент — наиболее вероятный класс.

---

## 7. `rtti_types.txt` — 1.0 МБ, 18 826 строк

Плоский список всех имён C++-типов, найденных в RTTI Type Descriptor'ах. По одному имени
на строку, отсортированы. Формат имени — MSVC type decorator:

```
.?AVCDOTA_BaseNPC_Hero@@              class CDOTA_BaseNPC_Hero
.?AUCDOTASubChallengeInfo@@           struct CDOTASubChallengeInfo
.?AW4TakeDamageFlags_t@@              enum TakeDamageFlags_t
.?AUCDefinition@CNmBlend1DNode@@      struct CNmBlend1DNode::CDefinition   (@ = вложенность)
```

---

## 8. `rtti_vtables.tsv` — 1.2 МБ, 20 566 строк

```
vtable_rva	class
0x02ffe378	.?AVCDOTALuaModifierEntry@@
```

Первая строка — заголовок. `vtable_rva` — RVA начала таблицы виртуальных функций
(то есть первая запись уже **после** слота `-1`, в котором лежит указатель на
Complete Object Locator). Зная `vtable_rva`, можно прочитать сами указатели на методы
из файла (`dllkit.py bytes <vtable_rva> --no-disasm`) и получить RVA виртуальных методов.

---

## 9. `index_categorized.txt` — 5.3 МБ

Человекочитаемый индекс: те же строки из `symbols.ndjson`, разложенные по 15 категориям.
Формат записи:

```
<текст строки> @ 0x<file_off>, 0x<file_off>, ...   [кол-во вхождений]
```

Категории:

| | Категория | Штук |
|---|---|---|
| A | RTTI — имена C++ типов | 18 826 |
| B | Сетевые атрибуты схемы данных (`CAttr_m_*`) | |
| C | Поля данных классов (`m_*`) | 8 977 |
| D | Имена методов (`Class::Method`) | 1 996 |
| E | Имена функций/констант в стиле Valve (`PREFIX_Name`) | 17 142 |
| F | Имена классов движка и игры (`CDOTA*`, `CSource*`, `CBase*`) | 426 |
| G | Protobuf: `.proto`-файлы и типы сообщений | 311 |
| H | Игровые ассеты и файлы (`.vmdl`, `.vmat`, `.vsnd`, `.vjs`, …) | 2 886 |
| I | Консольные переменные и команды (cvar / concommand) | 4 959 |
| J | Сообщения об ошибках, предупреждениях и ассертах | 2 556 |
| K | Форматные строки (видно аргументы функции) | 2 996 |
| L | Dota-идентификаторы (герои, способности, предметы, модификаторы) | 4 413 |
| M | Пути | 419 |
| N | Прочие идентификаторы | 25 120 |
| O | Человеко-читаемые тексты, описания, подсказки | 7 111 |

Классификация — по регулярным выражениям (см. `CATS` в `tools/build_data.py`), поэтому
категории пересекаются по смыслу и не являются истиной в последней инстанции.
Первая совпавшая категория выигрывает (порядок A→O).

**Самые полезные для понимания функций**: K (форматные строки — по `%s`/`%d`/`%f` видно
аргументы), J (ошибки — по ним видно, что функция проверяет), D (`Class::Method` —
фактически имена методов, сохранённые в логах/ассертах), I (cvar — что функция настраивает).

---

## 10. `_index.json` и `_index/*.idx.json`

`_index.json` — манифест:

```jsonc
{"files": {"function_strings.ndjson": {"size_bytes": 40826596, "records": 72946,
           "indexed_keys": 72946, "index_file": "_index/function_strings.idx.json"}}}
```

`_index/<имя>.idx.json` — карта `ключ → список байтовых смещений` начала строк в NDJSON-файле.
Значение **всегда список** (одному ключу может соответствовать несколько записей), поэтому
берите `v[0]`, если нужно первое вхождение.

| Файл индекса | Ключ | Значение |
|---|---|---|
| `_index/function_strings.idx.json` | `"54984"` — значение `function_id` | `[смещение]` |
| `_index/function_classes.idx.json` | `"54984"` — значение `function_id` | `[смещение]` |
| `_index/string_functions.idx.json` | точный текст строки | `[смещение, …]` |
| `_index/string_functions_byoff.idx.json` | десятичное `target_off` | `[смещение]` |

`exports.ndjson`, `imports.ndjson` и `symbols.ndjson` **не индексируются**: первые два
крошечные (читать целиком), а `symbols.ndjson` ищут подстрокой/регекспом (`dllkit.py find`),
причём точный текст там неоднозначен (128 361 записей, много дублей).

Чтение одной записи без загрузки файла (важно только, чтобы файл не был изменён после
построения индекса; `.gitattributes` фиксирует LF):

```python
import json
offs = json.load(open('data/_index/function_strings.idx.json'))['54984']
with open('data/function_strings.ndjson', encoding='utf-8') as f:
    f.seek(offs[0])
    rec = json.loads(f.readline())
```

⚠ Индекс нельзя собирать через `json.dump(..., sort_keys=True)`: этот флаг сортирует
**символы внутри строк-ключей** (`"62391592"` → `"      22"`), и поиск перестаёт работать.

---

## 11. `extras/` (не в git, создаётся `build_data.py --full`)

| Файл | Размер | Содержание |
|---|---|---|
| `strings_full.txt` | 62 МБ | дамп **всех** 743 734 строк образа, включая `.text`, `.pdata`, `.reloc`. Формат: `0x<file_off>  RVA=0x<rva>  VA=0x<va>  <секция> <ascii\|wide> len=<n>  \|<текст>\|` |
| `function_strings.tsv` | 17 МБ | плоская таблица: по одной строке на пару «функция — строка». Колонки: `function_id, begin_rva, end_rva, size, classes, code_rva, target_rva, file_off, section, kind, string` |
| `functions.ndjson` | 33 МБ | `{"id":0,"begin_rva":4461,"end_rva":5425,"size":964,"begin_va":…,"end_va":…,"unwind_rva":…}` — числа без `0x` |
| `symbols.tsv` | 10 МБ | `off, rva, va, section, kind, len, text` |

TSV/CSV удобны для pandas/Excel/ClickHouse; NDJSON — для построчной обработки и ИИ-агентов.

В `strings_full.txt` строки из `.text` — это в основном **случайные совпадения байтов кода**
с печатными символами, а не настоящие строки. В конце файла идут строки из области
Authenticode-подписи (после `.reloc`) — там читаются поля сертификатов (`Valve Corp.`,
`DigiCert, Inc.`, URL'и OCSP/CRL).
