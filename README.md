# dota2-server-dll-kit

**Полностью разобранный `server.dll` (Dota 2, Source 2) в текстовом виде + инструменты,
чтобы любой ИИ-агент или человек мог сам найти нужную функцию в этом бинарнике.**

Исходный файл — нативный PE32+ x86-64 DLL размером **88 194 712 байт (84.11 МБ)**,
retail-сборка Valve от **2026-10-24 16:33 UTC**, подписан Authenticode-сертификатом
**«Valve Corp.»**. PDB-путь внутри файла:

```
C:\buildworker\source2_dota_rel_2019_win64\build\_build_\game\server\_vpc_server_dota\unity\win64\_msvc_\Retail\server.pdb
```

SHA-256: `f7b7d300c9d32ddd07e9b211026288c8c017528938486414a0a01037981cc566`

Бинарник **не упакован и не зашифрован** (энтропия `.text` = 6.68), это **не .NET**.

---

## Что уже посчитано и лежит в `data/`

| Что | Сколько | Откуда |
|---|---|---|
| Экспортируемых точек входа | **6** | таблица экспорта (`CreateInterface`, `InstallSchemaBindings`, …) |
| Импортируемых функций | **744** из 7 DLL | таблица импорта; **316** имён MSVC разобраны деманглером |
| Функций с точными границами | **244 974** | `.pdata` / RUNTIME_FUNCTION |
| Имён C++-классов (RTTI) | **18 826** | Type Descriptor'ы в `.rdata`/`.data` |
| vtable → класс | **20 566** | x64 RTTI Complete Object Locator |
| Функций с определённым классом | **22 489** | функция грузит vtable/COL своего класса |
| Строк-символов (`.rdata`/`.data`) | **128 361** | тексты логов, ошибки, cvar, поля схемы, ассеты, protobuf |
| Строк во всём образе | **743 734** | включая случайные совпадения в `.text` |
| RIP-относительных ссылок в коде | **776 421** | дизассемблирование всех функций (capstone) |
| Функций, использующих строки | **72 946** | xref «строка → код → функция» |
| Строк с привязкой к функциям | **51 932** | обратный индекс |

Главная идея: **имена функций из retail-бинарника вырезаны линкером**, поэтому функция
идентифицируется тем, *что она загружает* — набором строк (логи, ошибки, имена полей,
имена Lua/VScript-методов) и классом, чью vtable она использует. Этой информации
достаточно, чтобы понять назначение функции.

---

## Быстрый старт

Python 3.8+, внешние зависимости не требуются (capstone нужен только для дизассемблирования).

```bash
python3 tools/dllkit.py find "Roshan"                 # найти строки/символы
python3 tools/dllkit.py who-uses "roshan_gold"        # какие функции её используют
python3 tools/dllkit.py who-uses "0x02d09b60"         # ...или по RVA / смещению строки
python3 tools/dllkit.py func 0x00bf03fd               # весь профиль функции по RVA
python3 tools/dllkit.py classes "CDOTA_BaseNPC"       # классы из RTTI + их vtable
python3 tools/dllkit.py cvars dota_                   # консольные переменные/команды
python3 tools/dllkit.py near 0x0305d188 --window 30   # соседние строки (контекст модуля)
python3 tools/dllkit.py pe                            # структура PE, экспорт, импорт, PDB, подпись
python3 tools/dllkit.py --limit 20 demangle           # разобрать декорированные имена импорта
python3 tools/dllkit.py who-uses 0x03b81f28           # ...или найти по RVA / смещению строки
python3 tools/dllkit.py stats                         # сводка по набору
python3 tools/selftest.py                             # 41 проверка целостности данных (без .dll)
```

К любой команде можно добавить **`--json`** — это режим для скриптов и ИИ-агентов.

### Реальный пример: «что делает эта функция?»

```bash
$ python3 tools/dllkit.py func 0x00bf03fd

ФУНКЦИЯ #54984
  RVA      : 0x00bf03fd – 0x00bf09d0   (1491 байт)
  VA       : 0x180bf03fd – 0x180bf09d0   (ImageBase 0x180000000)
  КЛАСС    : .?AVCDOTALuaModifierEntry@@
  ссылки   : в код 0, в .rdata 27, в .data 5
  СТРОКИ, которые использует функция (7):
    0x00bf044e -> [.rdata ascii] Error parsing lua modifier from string table!
    0x00bf0502 -> [.rdata ascii] Filename %s of modifier %s was not found!
    0x00bf0598 -> [.rdata ascii] Modifier script %s failed to find class named %s.
    0x00bf05c0 -> [.rdata ascii] ExtendInstance
    0x00bf06bf -> [.rdata ascii] DeclareFunctions
    ...
```

Вывод без единого символа отладки: это загрузчик Lua-модификаторов класса
`CDOTALuaModifierEntry` — он берёт запись из string table, ищет файл модификатора,
находит в скрипте класс и вызывает `ExtendInstance` / `DeclareFunctions`.

### Бонус: словарь скриптового API внутри бинарника

Самые «болтливые» функции — это реестраторы API. Строки в них идут тройками
«описание → имя метода → имя типа/исходный файл»:

```bash
$ python3 tools/dllkit.py func 0x006682f0 | head -12
ФУНКЦИЯ #27499
  RVA      : 0x006682f0 – 0x00670a3c   (34636 байт)
  СТРОКИ, которые использует функция (377):
    ...\src\public\tier0\utlrange.h
    CUtlRange
    Get the time spent on the server in the last frame
    FrameTime
    Get a random int within a range
    RandomInt
```

Так из retail-бинарника без единого символа извлекается **полный список серверного
скриптового API** (имена методов + их описания). Топ-12 таких функций — в
[`docs/ANALYSIS.md`](docs/ANALYSIS.md).

### Точки входа модуля (экспорт)

```bash
$ python3 tools/dllkit.py pe | sed -n '/ЭКСПОРТЫ/,/^$/p'
  ЭКСПОРТЫ (6 имён, ordinal base 1, внутреннее имя DLL «server.dll»):
    [1] BinaryProperties_GetValue    RVA 0x1dcfe00  VA 0x181dcfe00
    [2] CreateInterface              RVA 0x2d85b70  VA 0x182d85b70
    [3] ExtractModuleMetadata        RVA 0x1dd0580  VA 0x181dd0580
    [4] GetResourceManifestCount     RVA 0x2d9a2e0  VA 0x182d9a2e0
    [5] GetResourceManifests         RVA 0x2d9a2f0  VA 0x182d9a2f0
    [6] InstallSchemaBindings        RVA 0x2d9c2d0  VA 0x182d9c2d0
```

`CreateInterface` и `InstallSchemaBindings` — две функции, с которых движок поднимает
серверную логику. Удобная стартовая точка: `python3 tools/dllkit.py func 0x2d85b70`.

### Импорты с разобранными C++-именами

554 функции импортируются из `tier0.dll` (базовый слой Source 2), и 316 из них —
декорированные имена MSVC, которые набор разбирает встроенным деманглером:

```bash
$ python3 tools/dllkit.py --limit 8 demangle
  [tier0.dll] CBufferString::AppendFormat      | public virtual __cdecl
  [tier0.dll] KeyValues::LoadFromFile          | public virtual __cdecl
  [tier0.dll] KeyValues::FindKey               | public virtual __cdecl
  [tier0.dll] CUtlBuffer::EnsureCapacity       | public virtual __cdecl
  [tier0.dll] LoggingSystem_Log                | __cdecl
  [tier0.dll] CTSListBase::InternalPush        | private virtual __cdecl
  ...
```

Среди импортов `steam_api64.dll` — `SteamGameServer_GetHSteamUser`,
`SteamGameServer_RunCallbacks`, `SteamInternal_FindOrCreateGameServerInterface`:
это однозначно **выделенный игровой сервер Steam**, а не клиент.

Дизассемблирование (нужен сам `server.dll`):

```bash
python3 tools/dllkit.py --dll ./server.dll bytes 0x00bf03fd --size 256
```

---

## Структура репозитория

```
dota2-server-dll-kit/
├── README.md                     этот файл
├── AGENTS.md                     инструкция ДЛЯ ИИ-АГЕНТА (сценарии, форматы, grep-рецепты)
├── requirements.txt              capstone, numpy (нужны только для пересборки/дизассемблирования)
├── .gitignore / .gitattributes
├── data/                         готовые данные (~107 МБ в git, читать без бинарника)
│   ├── pe_info.json              84 КБ — заголовки, секции, каталоги, экспорт, импорт, PDB, подпись
│   ├── exports.ndjson            654 Б — 6 точек входа модуля
│   ├── imports.ndjson            169 КБ — 744 импорта (+ разобранные имена MSVC)
│   ├── _index.json               1 КБ — манифест файлов
│   ├── _index/*.idx.json          5.3 МБ — «ключ → байтовое смещение» для seek() в NDJSON
│   ├── rtti_types.txt            1.0 МБ — 18 826 имён C++-типов
│   ├── rtti_vtables.tsv          1.2 МБ — vtable_rva → класс
│   ├── function_classes.ndjson   4.6 МБ — 22 489 функций с классом
│   ├── index_categorized.txt     5.3 МБ — строки по 15 категориям
│   ├── string_functions.ndjson    15 МБ — строка → функции
│   ├── symbols.ndjson             20 МБ — 128 361 строка-символ с адресами
│   ├── functions.tsv              16 МБ — 244 974 функций (точные границы)
│   ├── function_strings.ndjson    41 МБ — функция → её строки + класс  ★ главный файл
│   └── extras/                   ~120 МБ — тяжёлые дубликаты (не в git, пересоздаются)
│       ├── strings_full.txt       62 МБ — дамп ВСЕХ 743 734 строк образа
│       ├── functions.ndjson       33 МБ — то же, что functions.tsv, в NDJSON
│       ├── function_strings.tsv   17 МБ
│       └── symbols.tsv            10 МБ
├── tools/
│   ├── dllkit.py                 единый CLI: find / who-uses / func / near / bytes / pe /
│   │                             classes / cvars / demangle / stats
│   ├── selftest.py               41 проверка целостности данных (работает без .dll)
│   ├── build_data.py             пересборка ВСЕХ данных из любого PE32+ бинарника
│   ├── build_index.py            построение _index/*.idx.json
│   ├── get_dll.py                скачать/найти server.dll и проверить SHA-256
│   └── _pelib.py                 минимальный PE-парсер без зависимостей
└── docs/
    ├── DATA_FORMATS.md           точное описание каждого файла и поля
    └── ANALYSIS.md               что удалось установить о бинарнике + ограничения метода
```

---

## Для ИИ-агентов

Откройте **[`AGENTS.md`](AGENTS.md)**. Там:

* готовый сценарий «найти функцию по её поведению» (5 шагов),
* таблица «какой файл читать первым» (от 5 КБ до 62 МБ) — чтобы не сжигать контекст,
* точные форматы всех NDJSON-записей,
* способ читать одну запись через `seek()` по `_index/*.idx.json` без загрузки 41 МБ,
* grep-рецепты без Python,
* явный список того, чего в данных **нет** (имена функций, экспорт, импорты, исходный код),
  чтобы агент не выдумывал.

---

## Пересборка данных (для другого или обновлённого бинарника)

```bash
pip install -r requirements.txt          # numpy + capstone
python3 tools/get_dll.py --url "<ссылка>" --sha256 f7b7d300...   # или положите server.dll вручную
python3 tools/build_data.py --dll ./server.dll          # ~2 мин, основные данные
python3 tools/build_data.py --dll ./server.dll --full   # + data/extras/ (62 МБ строк, CSV/TSV)
python3 tools/build_index.py                            # индексы смещений
```

`build_data.py` не привязан к Dota 2: он разбирает любой PE32+ — `.pdata` (границы функций),
RTTI (классы), строки, и строит xref через capstone. Тем же набором можно разобрать
`client.dll`, `engine.dll`, `host.dll` и прочие модули Source 2.

---

## Git / GitHub

* Репозиторий ≈ **107 МБ**, Git LFS **не требуется**: самый большой файл
  `function_strings.ndjson` = 39 МБ (лимит GitHub — 100 МБ на файл).
* `data/extras/` (~120 МБ) в git **не коммитится** (см. `.gitignore`) — пересоздаётся
  командой `python3 tools/build_data.py --dll <путь> --full`. Там лежат дубликаты
  основных данных в других форматах (полный дамп всех строк образа, NDJSON-вариант
  таблицы функций, TSV-выгрузки) — для основного сценария они не нужны.
* Сам `server.dll` (84 МБ) в репозиторий не кладётся: это объект авторского права Valve.
  Для работы CLI он не нужен — все данные уже извлечены. Он требуется только для команд
  `bytes` (hex/дизассемблирование) и для пересборки.

```bash
git init && git add . && git commit -m "Dota 2 server.dll: strings, functions, RTTI classes, xrefs"
git remote add origin https://github.com/<you>/dota2-server-dll-kit.git
git push -u origin main
```

---

## Правовая оговорка

`server.dll` — проприетарный код Valve Corporation, распространяется через Steam.
В репозитории нет самого бинарника — только извлечённые из него строки, адреса и
структурные метаданные, полученные из легально установленной копии игры.
Используйте для исследования и обучения; не используйте для читов и нарушения
условий использования Steam/Dota 2.
