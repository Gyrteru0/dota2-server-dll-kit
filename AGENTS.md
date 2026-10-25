# AGENTS.md — инструкция для ИИ-агента

Ты анализируешь `server.dll` — серверный модуль **Dota 2** на движке **Source 2**
(PE32+ x86-64, 88 194 712 байт, retail-сборка Valve от 2026-10-24, подпись «Valve Corp.»).

Имена внутренних функций из бинарника **вырезаны линкером**. Имена, которые у тебя есть:

| Источник имён | Что даёт |
|---|---|
| `.pdata` (RUNTIME_FUNCTION) | точные границы **244 974** функций → RVA/размер каждой |
| RTTI (Complete Object Locator) | **18 826** имён C++-классов и **20 566** vtable → класс для **22 489** функций |
| строки в `.rdata`/`.data` | **128 361** символ: тексты логов, ошибки, cvar, имена полей схемы, ассеты, protobuf |
| xref (дизассемблирование) | **776 421** RIP-относительная ссылка → какие строки использует каждая функция |
| таблица экспорта | **6** точек входа (`CreateInterface`, `InstallSchemaBindings`, …) |
| таблица импорта | **744** функции из 7 DLL, из них **316** с разобранными C++-именами (`KeyValues::FindKey`, `LoggingSystem_Log`, …) |

**Ключевой приём**: функция идентифицируется не именем, а *набором строк, которые она
загружает* (тексты логов/ошибок, имена полей, имена Lua/VScript-методов) + *классом,
чью vtable она загружает*. Этого достаточно, чтобы понять, что функция делает.

---

## 1. Быстрый старт (ничего устанавливать не нужно)

Все данные уже лежат в `data/`. Самый простой путь — CLI:

```bash
python3 tools/dllkit.py find "Roshan"                       # найти строки
python3 tools/dllkit.py who-uses "roshan_gold"              # какие функции её используют
python3 tools/dllkit.py who-uses "0x02d09b60"               # то же по RVA строки
python3 tools/dllkit.py who-uses "47225696"                 # то же по смещению в файле
python3 tools/dllkit.py func 0x00bf03fd                     # всё о функции по RVA
python3 tools/dllkit.py classes "CDOTA_BaseNPC"             # классы из RTTI
python3 tools/dllkit.py near 0x0305d188 --window 30         # соседние строки (контекст модуля)
python3 tools/dllkit.py pe                                  # структура PE, экспорт, импорт, подпись
python3 tools/dllkit.py --limit 20 demangle                 # разобрать декорированные имена импорта
python3 tools/dllkit.py bytes 0x00bf03fd --size 256         # hex + дизассемблирование (нужен server.dll)
```

**Добавь `--json` к любой команде — получишь структурированный вывод.** Это предпочтительный
режим для агента. Пример:

```bash
python3 tools/dllkit.py who-uses "Modifier script %s failed to find class named %s." --json
python3 tools/dllkit.py func 0x00bf03fd --json
```

---

Глобальные флаги `--json`, `--limit N`, `--data ПУТЬ`, `--dll ПУТЬ` работают и **до**, и
**после** имени команды (`dllkit.py --limit 20 find x` ≡ `dllkit.py find x --limit 20`).
Код выхода: `0` — успех, `1` — ничего не найдено, `2` — нужен сам `server.dll` (`bytes`).

## 2. Стандартный сценарий «найти функцию по её поведению»

0. Если речь о точке входа модуля — начни с `data/exports.ndjson`:
   `CreateInterface` (RVA 0x02D85B70) и `InstallSchemaBindings` (RVA 0x02D9C2D0) —
   две функции, с которых движок поднимает серверную логику. Дальше:
   `dllkit.py func 0x02D85B70 --json`.
1. **Сформулируй текст**, который функция наверняка содержит: сообщение об ошибке, имя cvar,
   имя поля, имя Lua-метода, имя ассета.
2. `dllkit.py find "<фрагмент>" --json` → получишь список строк с `file_off` и `rva`.
3. `dllkit.py who-uses "<точная строка | RVA | смещение в файле>" --json` → список функций: `begin_rva`, `end_rva`,
   `size`, `classes`.
4. `dllkit.py func <begin_rva> --json` → **полный профиль функции**: класс, счётчики ссылок
   (`refs_code`/`refs_rdata`/`refs_data`) и все строки, которые она использует, с адресами
   инструкций (`code_rva`).
5. Если нужен код: `dllkit.py bytes <begin_rva> --size <size> --json` (требуется сам `server.dll`;
   нужен `pip install capstone`).

Если строка не нашлась в `who-uses` — значит, код на неё не ссылается RIP-относительно
(например, она лежит в статической таблице, на которую указывает vtable/структура).
Тогда используй `near <file_off>` — посмотри соседние строки: они принадлежат той же таблице,
и по ним понятно, что это за массив (список cvar, таблица сообщений, схема полей и т.д.).

---

## 3. Файлы данных и их назначение

Читай в этом порядке (от дешёвых к дорогим):

| Файл | Размер | Когда читать |
|---|---|---|
| `data/pe_info.json` | 84 КБ | всегда первым: размеры, секции, PDB, экспорт, импорт, подпись |
| `data/exports.ndjson` | 654 Б | 6 точек входа модуля (RVA каждой) |
| `data/imports.ndjson` | 169 КБ | 744 импорта; у декорированных есть поле `demangled` |
| `data/_index.json` | 1 КБ | манифест: сколько записей в каждом файле |
| `data/_index/*.idx.json` | 5.3 МБ | «ключ → байтовое смещение» — точечное чтение записи через `seek()`, без загрузки файла |
| `data/rtti_types.txt` | 1.0 МБ | список всех C++-классов (grep по имени) |
| `data/rtti_vtables.tsv` | 1.2 МБ | `vtable_rva \t class` |
| `data/function_classes.ndjson` | 4.6 МБ | класс → функции (22 489 записей) |
| `data/index_categorized.txt` | 5.3 МБ | строки, разложенные по 15 категориям (RTTI, cvar, ассеты, ошибки, форматные строки…) |
| `data/string_functions.ndjson` | 15 МБ | строка → функции, которые на неё ссылаются |
| `data/symbols.ndjson` | 19 МБ | все 128 361 строк-символов с адресами |
| `data/functions.tsv` | 16 МБ | все 244 974 функций (точные границы, размеры) |
| `data/function_strings.ndjson` | 41 МБ | функция → все её строки + класс (главный файл) |
| `data/extras/strings_full.txt` | 62 МБ | дамп **всех** строк образа, включая `.text` (опционально) |

`data/extras/` может отсутствовать — это тяжёлые дубликаты, они пересоздаются командой
`python3 tools/build_data.py --dll <путь> --full`.

---

## 4. Форматы

**NDJSON** — по одному JSON-объекту на строку. Потоково читается построчно, не грузи целиком.

`data/functions.tsv` (заголовок + 244 974 строки, отсортированы по `begin_rva`):
```
id	begin_rva	end_rva	size	begin_va	end_va	unwind_rva
54984	0x00bf03fd	0x00bf09d0	1491	0x180bf03fd	0x180bf09d0	0x0503e9c0
```

`data/function_strings.ndjson`:
```json
{"function_id":54984,"begin_rva":"0x00bf03fd","end_rva":"0x00bf09d0","size":1491,
 "begin_va":6454969341,"end_va":6454970832,
 "classes":[".?AVCDOTALuaModifierEntry@"],
 "refs_code":0,"refs_rdata":27,"refs_data":5,"num_strings":7,
 "strings":[{"code_rva":"0x00bf044e","target_rva":"0x0305eb88","file_off":"0x0305d188",
             "section":".rdata","kind":"ascii","text":"Error parsing lua modifier from string table!"}]}
```

`data/string_functions.ndjson`:
```json
{"text":"roshan_gold","target_rva":"0x02d09b60","target_off":47225696,"num_functions":2,
 "functions":[{"id":75886,"begin_rva":"0x00f297f0","end_rva":"0x00f29813",
               "begin_va":6451533808,"size":35}]}
```

`data/symbols.ndjson`:
```json
{"off":"0x0305d188","rva":"0x0305eb88","va":6459489160,"section":".rdata",
 "kind":"ascii","len":44,"text":"Error parsing lua modifier from string table!"}
```

**Точечный доступ без полного чтения**: `data/_index/<имя>.idx.json` — карта
`ключ → байтовое смещение` в соответствующем NDJSON. Ключ: `function_id` для
`function_strings`/`function_classes`, `id` для `functions`, `text` для
`string_functions`/`symbols`. Чтение одной записи:

```python
import json
dd='data'
idx=json.load(open(f'{dd}/_index/function_strings.idx.json'))
off=idx['54984']
with open(f'{dd}/function_strings.ndjson',encoding='utf-8') as f:
    f.seek(off); rec=json.loads(f.readline())
```

**RVA vs VA vs file_off**: `VA = RVA + ImageBase (0x180000000)`. `file_off` — позиция в файле.
Пересчёт: для `.text` `file_off = rva - 0xC00`, для `.rdata` `file_off = rva - 0x1A00`,
для `.data` `file_off = rva - 0x1C00`. Точные пары (va/raw) — в `data/pe_info.json`.

---

## 5. Полезные grep-рецепты (без Python)

```bash
# все cvar/команды, начинающиеся с dota_
grep -E '^dota_[a-z0-9_]+ @' data/index_categorized.txt | head -50

# все классы способностей
grep '^\.?AVCDOTA_Ability' data/rtti_types.txt | head -50

# какие функции грузят vtable класса CDOTA_BaseNPC_Hero
grep -F '"classes":[".?AVCDOTA_BaseNPC_Hero@@"]' data/function_classes.ndjson | head

# все тексты ошибок про рошана
grep -i 'roshan' data/index_categorized.txt | head -30

# найти функцию по фрагменту лога и сразу получить её RVA
grep -F 'SetupGameKeyValues took' data/function_strings.ndjson | head -1 | python3 -c "import sys,json;r=json.loads(sys.stdin.read());print(r['begin_rva'],r['end_rva'],r['classes'])"
```

---

## 6. Пересборка данных из другого/обновлённого server.dll

```bash
pip install numpy capstone          # numpy и capstone нужны только для xref
python3 tools/build_data.py --dll /путь/к/server.dll          # основные данные (~2 мин)
python3 tools/build_data.py --dll /путь/к/server.dll --full   # + extras/ (62 МБ строк, CSV/TSV)
python3 tools/build_index.py                                   # индексы смещений
```

`tools/build_data.py` не зависит от конкретного бинарника: он работает с любым PE32+
(разбирает `.pdata`, RTTI, строки, строит xref через capstone). Поэтому этим же набором
можно анализировать `client.dll`, `engine.dll` и другие модули Source 2 — достаточно
пересобрать `data/` с `--dll <другой файл>`.

---

## 7. Чего в данных НЕТ (не выдумывай)

* **Имён функций.** Их нет в бинарнике. Любое «имя функции» — это либо имя C++-класса из RTTI,
  либо имя метода из строки `Class::Method` (категория D индекса), либо имя из лог-сообщения.
  Не приписывай функции имя, которого нет в данных.
* **Имён внутренних функций.** Экспорт (6 имён) и импорт (744 имени) читаются точно, но
  остальные 244 974 функции бинарника имён не имеют — только RVA, размер, класс и строки.
* **Исходного кода.** Retail-бинарник без PDB. Псевдокод возможен только через полноценный
  декомпилятор (Ghidra/IDA); данный набор даёт структурную карту и привязку строк к функциям.
* **Строк короче 4 символов** и строк, которые не попали в категории индекса (они есть в
  `data/extras/strings_full.txt`).

Когда данных не хватает — так и скажи и предложи следующий шаг (`bytes` + дизассемблирование,
пересборка с `--full`, либо анализ в Ghidra).
