# ANALYSIS.md — что установлено о `server.dll` и как это было получено

## 1. Идентификация файла

| Признак | Значение |
|---|---|
| Размер | 88 194 712 байт (84.11 MiB) |
| Формат | PE32+ (`IMAGE_NT_OPTIONAL_HDR64_MAGIC` = 0x20B), DLL, x86-64 |
| Machine | 0x8664 = AMD64 |
| ImageBase | 0x180000000 |
| EntryPoint RVA | 0x2DA21B8 |
| Subsystem | 2 = WINDOWS_CUI (консольный — это выделенный сервер, не оконное приложение) |
| DllCharacteristics | 0x160 = HIGH_ENTROPY_VA \| DYNAMIC_BASE (ASLR) \| NX_COMPAT (DEP) \| TERMINAL_SERVER_AWARE |
| TimeDateStamp | 1792859597 = **2026-10-24 16:33:17 UTC** |
| Секций | 5: `.text`, `.rdata`, `.data`, `.pdata`, `.reloc` |
| PDB | `C:\buildworker\source2_dota_rel_2019_win64\build\_build_\game\server\_vpc_server_dota\unity\win64\_msvc_\Retail\server.pdb` |
| PDB GUID / age | `698B48EE6F0A41BCAE586273770EE7BE` / 30 |
| Подпись | Authenticode, 11 416 байт, сертификат **Valve Corp.** (Bellevue, Washington), выдан DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, срок 2024-10-12 … 2027-10-08; метка времени DigiCert SHA256 RSA4096 Timestamp Responder, штамп 2026-10-24 16:33:27 UTC |
| SHA-256 | `f7b7d300c9d32ddd07e9b211026288c8c017528938486414a0a01037981cc566` |

**Вывод:** это серверная библиотека игры **Dota 2** на движке **Source 2**. PDB-путь прямо
указывает на проект `_vpc_server_dota` (VPC = Valve Project Creator) в конфигурации **Retail**
и **unity-сборке** (все `.cpp` сливаются в одну единицу компиляции — именно поэтому файл
занимает 84 МБ вместо десятка мелких объектных модулей). Штамп подписи совпадает со
штампом линковки с точностью до 10 секунд: файл подписан сразу после сборки.

### Упакован ли / зашифрован ли?

Нет.

| Секция | Размер | Энтропия | Интерпретация |
|---|---|---|---|
| `.text` | 48.7 МБ | 6.68 | обычный скомпилированный x86-64 код (упакованный код дал бы 7.8–8.0) |
| `.rdata` | 27.5 МБ | 4.88 | константы, строки, vtable |
| `.data` | 4.5 МБ (в файле) | 3.95 | инициализированные глобальные данные |
| `.pdata` | 2.9 МБ | 7.14 | плотно упакованные 12-байтные структуры RUNTIME_FUNCTION |
| `.reloc` | 4.5 МБ | 5.45 | таблица перемещений |

Каталог `CLR_RUNTIME` пуст → это **не .NET** сборка, декомпиляция в C# невозможна.
Каталог `RESOURCE` пуст → ресурсов (иконок, диалогов) в DLL нет.

---

## 2. Что отсутствует в файле (и почему)

* **Символы функций.** Retail-сборка без PDB: ни COFF-таблицы символов
  (`PointerToSymbolTable` = 0, `NumberOfSymbols` = 0), ни отладочных имён.
* **Имена внутренних (не экспортируемых) функций.** Их нет: ни COFF-таблицы символов
  (`PointerToSymbolTable` = 0, `NumberOfSymbols` = 0), ни локальных символов PDB.
  Экспорт и импорт при этом читаются полностью — см. раздел 3.0.

Таблицы экспорта и импорта лежат в файловой части `.data` (RVA `0x048AA370` и `0x048AA464`;
`raw_size` секции `.data` = 4 494 848 байт покрывает RVA до `0x04CF9A00`, так что обе
таблицы присутствуют физически). BSS-хвост `.data` (7 309 052 байт) к ним отношения не имеет.

Поэтому **внутренние функции идентифицируются не именами, а адресами + тем, что они
загружают** (строки, vtable, классы) — но 6 экспортируемых точек входа и 744 импортируемые
функции (из них 316 с разобранными C++-именами) известны точно.

---

## 3. Что удалось восстановить

### 3.0. Экспорт и импорт — читаются из файла полностью

**Экспорт (6 имён, ordinal base 1, внутреннее имя DLL — `server.dll`):**

| Ordinal | Имя | RVA | VA | Назначение |
|---|---|---|---|---|
| 1 | `BinaryProperties_GetValue` | 0x01DCFE00 | 0x181DCFE00 | чтение бинарных свойств модуля |
| 2 | `CreateInterface` | 0x02D85B70 | 0x182D85B70 | **главная точка входа**: отдаёт фабрику интерфейсов (`IServerGameDLL`, `Source2Server` и др.) по имени версии |
| 3 | `ExtractModuleMetadata` | 0x01DD0580 | 0x181DD0580 | метаданные модуля для системы ресурсов |
| 4 | `GetResourceManifestCount` | 0x02D9A2E0 | 0x182D9A2E0 | сколько манифестов ресурсов требует модуль |
| 5 | `GetResourceManifests` | 0x02D9A2F0 | 0x182D9A2F0 | сами манифесты ресурсов |
| 6 | `InstallSchemaBindings` | 0x02D9C2D0 | 0x182D9C2D0 | **подключение схемы данных сущностей** (поля `m_*`, сетевые атрибуты) |

Это стандартный набор экспорта серверного модуля Source 2. `CreateInterface` и
`InstallSchemaBindings` — две функции, с которых движок (`engine.dll` / `host.dll`)
поднимает серверную логику; их RVA — отличная стартовая точка для анализа в Ghidra/IDA.

Файлы: `data/exports.ndjson`, `pe_info.json` → `exports`.

**Импорт (7 DLL, 744 функции):**

| DLL | Функций | Что это |
|---|---|---|
| `tier0.dll` | 554 | базовый слой Source 2: строки, контейнеры, логирование, потоки, KV3 |
| `KERNEL32.dll` | 121 | CRT-обвязка и WinAPI (файлы, память, потоки, консоль) |
| `GDI32.dll` | 22 | графика (минимально — сервер консольный) |
| `USER32.dll` | 16 | окна/сообщения (минимально) |
| `WS2_32.dll` | 15 | сокеты: `socket`, `connect`, `send`, `recv`, `select`, `WSAStartup` |
| `steam_api64.dll` | 13 | Steam GameServer API |
| `ADVAPI32.dll` | 3 | реестр/безопасность |

**316 импортируемых имён из `tier0.dll` декорированы по правилам MSVC**, и их удалось
разобрать встроенным деманглером (`tools/dllkit.py demangle`). Это даёт точные имена
используемых методов базового слоя:

```
KeyValues::LoadFromFile        KeyValues::FindKey           KeyValues::AddInt
CBufferString::AppendFormat    CBufferString::FixSlashes    CBufferString::StripExtension
CUtlBuffer::EnsureCapacity     CUtlBuffer::SeekGet          CUtlString::Replace
CUniformRandomStreamImpl<...>::SetSeed / RandomInt / RandomFloatExp
CTSListBase::InternalPush      CTSListBase::InternalPop     CThreadMultiWaitEvent::Set
LoggingSystem_Log              LoadKV3Text_NoHeader         DebugPrintKV3
CVariableBitStringBase::Resize CUtlScratchMemoryPool::AllocAligned
```

Важное наблюдение: `steam_api64.dll` импортирует именно `SteamGameServer_*`
(`SteamGameServer_GetHSteamUser`, `SteamGameServer_GetHSteamPipe`, `SteamGameServer_RunCallbacks`)
вместе с `SteamInternal_FindOrCreateGameServerInterface` — это однозначно подтверждает,
что модуль работает как **выделенный игровой сервер Steam**, а не как клиент.

Файлы: `data/imports.ndjson` (у декорированных имён есть поле `demangled`),
`pe_info.json` → `imports`.

---

### 3.1. Границы всех функций — 244 974 штуки

Каталог `EXCEPTION` (`.pdata`) содержит массив `RUNTIME_FUNCTION {BeginAddress, EndAddress,
UnwindInfoAddress}` — по одной записи на каждую функцию, у которой есть unwind-информация.
Это единственный полностью надёжный источник границ функций в retail-бинарнике, и он даёт
практически полный перечень кода.

* записей: **244 974** (`2 939 688 / 12`);
* размер функции: минимум 1 байт, медиана **77 байт**, максимум **54 954 байта**;
* записи отсортированы по возрастанию `BeginAddress` → поиск «какая функция содержит адрес X»
  делается бинарным поиском;
* «chained»-записей (`UnwindInfoAddress == BeginAddress`) нет — все unwind-структуры отдельны.

Файл: `data/functions.tsv` (15.6 МБ); NDJSON-вариант создаётся при `--full`
и кладётся в `data/extras/functions.ndjson`.

### 3.2. Имена C++-классов — 18 826 типов

В `.rdata`/`.data` лежат MSVC RTTI Type Descriptor'ы: 16-байтный заголовок
(`pVFTable`, `spare`) + декорированное имя типа (`.?AVClass@@`). Найдено **18 826** уникальных
имён — это фактический список всех классов, структур и перечислений, скомпилированных в DLL.

Файлы: `data/rtti_types.txt`, категория A в `data/index_categorized.txt`.

По префиксам:

| Префикс | Значение | Пример |
|---|---|---|
| `.?AV` | class | `.?AVCDOTA_BaseNPC_Hero@@` |
| `.?AU` | struct | `.?AUCDOTASubChallengeInfo@@` |
| `.?AW` | enum | `.?AW4TakeDamageFlags_t@@` |
| `@` внутри | вложенность / шаблон | `.?AUCDefinition@CNmBlend1DNode@@` = `CNmBlend1DNode::CDefinition` |

Среди имён видны целые подсистемы: `CDOTA_*` (игра), `CNm*` (анимационный граф Nemesis),
`CPulse*` (визуальные скрипты Pulse), `CAnim*`, `CParticle*`, `CPhys*`, `CSchema*`,
`CVScript*`, `CBaseEntity*`, `CNetMessagePB<...>` (шаблоны сетевых сообщений).

### 3.3. vtable → класс — 20 566 таблиц

x64 RTTI устроен так: `vtable[-1]` → `CompleteObjectLocator` (COL), а COL содержит
`pTypeDescriptor` как **RVA**. Алгоритм восстановления:

1. найти все Type Descriptor'ы (по строке `.?A...` с 16-байтным заголовком перед ней);
2. найти все COL'ы: 4-байтное поле, равное RVA какого-то TD, при `signature == 1`
   (x64) на 12 байт левее;
3. найти все 8-байтные значения `ImageBase + RVA(COL)` в `.rdata`/`.data` — позиция + 8
   и есть начало vtable.

Результат: **20 566** пар `vtable_rva → class`. Файл: `data/rtti_vtables.tsv`.

### 3.4. Класс для 22 489 функций

Пролог большинства методов Source 2 не обращается к vtable, но конструкторы, деструкторы
и методы, вызывающие виртуальные функции, загружают адрес vtable через `lea reg,[rip+disp]`.
Если функция ссылается на vtable или COL класса — с высокой вероятностью это метод/конструктор
этого класса.

* функций с определённым классом: **22 489** из 244 974 (9.2 %);
* уникальных классов, задействованных так: **11 730**;
* у 72 946 функций есть хотя бы одна ссылка на строку.

Топ классов по числу обращений к их vtable/COL:

| Ссылок | Класс | Что это |
|---|---|---|
| 1768 | `CNetMessage` | базовый класс сетевого сообщения |
| 352 | `CEntityIOOutput` | выходы логики сущностей Source 2 |
| 287 | `CBroadcastRecipientFilter` | фильтр получателей рассылки |
| 182 | `IRecipientFilter` | интерфейс фильтра получателей |
| 165 | `CReliableBroadcastRecipientFilter` | надёжная рассылка |
| 131 | `CModifierFactoryDictionary` | фабрика модификаторов Dota |
| 112 | `CTraceFilter` | фильтры трассировки лучей (физика) |
| 94 | `CNetMessagePB<192, CDOTAUserMsg_ContextualTip, ...>` | шаблон protobuf-сообщения |
| 75 | `CDOTABaseAbility` | базовый класс способности |
| 74 | `CMsgDOTACombatLogEntry` | запись боевого лога |
| 61 | `CDOTAItemSystem` | система предметов |
| 59 | `CDOTA_BotMode` | режимы поведения ботов |

Файл: `data/function_classes.ndjson`.

### 3.5. Строки — 128 361 «символ» и 743 734 строки образа

* `.rdata` + `.data`, длина ≥ 4: **128 361** строка → `data/symbols.ndjson`.
  Это осмысленный словарь бинарника.
* Весь образ (включая `.text`, `.pdata`, `.reloc`, область подписи): **743 734** строки →
  `data/extras/strings_full.txt` (62 МБ). Строки из `.text` — в основном случайные совпадения
  байтов кода с печатными символами, а не настоящие строки.
* Широких строк (UTF-16LE) всего **541** — это имена API-функций и DLL для позднего
  связывания (`kernel32`, `api-ms-win-core-fibers-l1-1-1`, `api-ms-win-core-synch-l1-2-0`).

Категории осмысленных строк (полный список — `data/index_categorized.txt`):

| Категория | Штук | Пример |
|---|---|---|
| A. RTTI-имена типов | 18 826 | `.?AVCDOTA_Ability_Special_Bonus_Magic_Resistance_12@@` |
| N. Прочие идентификаторы | 25 120 | `__RegisterGameEventListeners` |
| E. Имена в стиле Valve | 17 142 | `DOTA_CM_RoshanTimer` |
| C. Поля данных `m_*` | 8 977 | `m_flAttackAnimPoint` |
| O. Человекочитаемые тексты | 7 111 | описания, подсказки, лог-сообщения |
| I. cvar / concommand | 4 959 | `dota_ability_debug`, `sv_cheats`, `npc_*` |
| L. Dota-идентификаторы | 4 413 | `ability_draft_select_hero`, `roshan_gold` |
| K. Форматные строки | 2 996 | `Filename %s of modifier %s was not found!` |
| H. Ассеты и файлы | 2 886 | `models/heroes/tidehunter/tidehunter_fish_pickup.vmdl` |
| J. Ошибки и ассерты | 2 556 | `Error parsing lua modifier from string table!` |
| D. `Class::Method` | 1 996 | `CDOTA_Ability_Kunkka_GhostShip::OnProjectileHit` |
| M. Пути | 419 | `game/dota/...` |
| F. Имена классов движка | 426 | `CDOTAGameManager` |
| G. Protobuf-типы | 311 | `CDOTAUserMsg_ContextualTip`, `AddModifierEvent` |

### 3.6. Скриптовые API (самое ценное для понимания «что делает функция»)

Категория D содержит **1 996** имён вида `Class::Method` из **557** классов — это имена,
сохранённые в строках для VScript/Pulse-биндингов, логов и ассертов. Топ:

| Методов | Класс | Что это |
|---|---|---|
| 180 | `CDOTA_Bot_Script` | скриптовый API ботов |
| 85 | `CPulseMathlib` | математическая библиотека Pulse-графов |
| 78 | `CBaseEntity_API` | VScript API базовой сущности |
| 48 | `CFuncMover_API` | VScript API движущихся платформ |
| 47 | `CDOTABaseAbility_BotScript` | API способностей для ботов |
| 29 | `CBaseModelEntity_API` | VScript API модельных сущностей |
| 24 | `CDOTA_TeamCommander` | командир команды (боты) |
| 22 | `CDOTA_ScriptedSpawner_API` | VScript API спавнеров |
| 22 | `CDynamicProp_API`, `CTestPulseIO_API` | пропы и тестовые Pulse-IO |

Примеры реальных имён методов игры, извлечённых из строк:

```
CDOTA_BaseNPC::UnitThink                          CDOTA_BaseNPC::DamageImpact
CDOTA_BaseNPC::DoBotScriptBaseThink               CDOTA_BaseNPC::LoadNPCData
CDOTA_BaseNPC::StartGesture                       CDOTA_BaseNPC::UpdateAggressiveStance
CDOTAGameRules::State_Enter_WAIT_FOR_PLAYERS_TO_LOAD
CDOTAGameRules::State_Think_WAIT_FOR_PLAYERS_TO_LOAD
CDOTAGameRules::CalcNumLoadingPlayersAndFailure   CDOTAGameRules::UpdatePlayerAccolades
CDOTAGameRules::ClientMsg_GiftPlayer              CDOTAGameRules::SendPreGameItemPurchasesToSteamLearn
CDOTA_Ability_Kunkka_GhostShip::OnProjectileHit   CDOTA_Ability_Kunkka_GhostShip::AddActiveCannonball
CDOTA_Ability_Rubick_SpellSteal::SetSpellStealAbilityIndex
CDOTA_Ability_NianCharge::OnChannelFinish         CDOTA_AttackRecordManager::AddNewAttackRecord
```

Это **не** символы из таблицы экспорта — это строки, которые движок использует для
регистрации VScript-методов, для логов и для ассертов. Но по ним название метода
восстанавливается точно, и дальше его можно связать с конкретной функцией через xref.

### 3.6a. Регистрация скриптового API — «словарь» методов прямо в бинарнике

Самые большие по числу строк функции оказались **реестраторами API**. Пример — функция
`#27499` (RVA `0x006682F0`–`0x00670A3C`, **34 636 байт**, 377 строк, 206 ссылок в код,
431 в `.rdata`, 566 в `.data`). Её строки идут характерными тройками:

```
Get a random int within a range          <- описание метода (показывается в документации/консоли)
RandomInt                                <- имя метода в скриптовом API
C:\buildworker\source2_dota_rel_2019_win64\build\src\public\tier0\utlrange.h   <- файл-источник
CUtlRange                                <- имя типа
DMG_%s / FrameTime / ...
```

То есть бинарник содержит **полный словарь серверного скриптового API**: имя метода,
его человекочитаемое описание и имя типа. Это самый прямой способ понять, какие
возможности сервер暴露 scripted-логике, и он извлекается без единого отладочного символа.

Топ-12 функций по числу используемых строк (это кандидаты на «главные реестраторы»):

| # | RVA | Размер, байт | Строк |
|---|---|---|---|
| 1 | 0x02515197 | 54 954 | 1030 |
| 2 | 0x0241B91F | 51 528 | 706 |
| 3 | 0x017EB2E9 | 40 579 | 531 |
| 4 | 0x023D7512 | 32 203 | 500 |
| 5 | 0x01F66480 | 32 893 | 483 |
| 6 | 0x006682F0 | 34 636 | 377 |
| 7 | 0x018B6E50 | 34 245 | 343 |
| 8 | 0x0175A73C | 22 088 | 317 |
| 9 | 0x0237BA17 | 25 445 | 316 |
| 10 | 0x016CBE00 | 26 853 | 280 |
| 11 | 0x0227D170 | 26 646 | 271 |
| 12 | 0x00478304 | 11 191 | 255 |

Для сравнения: медианный размер функции, использующей строки, — **170 байт**.

### 3.7. cvar и команды

Найдено **4 959** строк, похожих на консольные переменные/команды. Распределение по префиксам:

| Префикс | Штук | Префикс | Штук |
|---|---|---|---|
| `dota_` | 1095 | `player_` | 122 |
| `item_` | 760 | `ent_` | 102 |
| `npc_` | 474 | `mana_` | 73 |
| `nav_` | 301 | `team_` | 66 |
| `sv_` | 142 | `ability_` | 65 |

Примеры: `sv_cheats`, `sv_airaccelerate`, `sv_client_predict`, `dota_ability_debug`,
`dota_ability_draft_dump_heroes`, `dota_1v1_skip_strategy`, `dota_731_teaser_enabled`,
`dota_ability_contribution_assert_minimum`.

Обратите внимание: по одному только имени cvar в строках **нельзя** сказать, где он
зарегистрирован — для этого нужен xref (`dllkit.py who-uses "sv_cheats"`).

### 3.8. Ассеты

Строки с расширениями файлов Source 2:

| Расширение | Штук | Что это |
|---|---|---|
| `.vpcf` | 2667 | системы частиц (Particle Configuration File) |
| `.vmdl` | 127 | модели |
| `.vdata` | 30 | данные анимаций |
| `.vmat` | 16 | материалы |
| `.png` / `.vtex` | 11 / 8 | текстуры |
| `.vsndevts` | 10 | события звука |
| `.lua` | 6 | Lua-скрипты |
| `.cfg` / `.sav` | 4 / 4 | конфиги и сохранения |

Примеры: `models/props_gameplay/pig.vmdl`, `models/heroes/rubick/rubick_tree.vmdl`,
`materials/physics/wireframe_basic.vmat`, `materials/tools/show_collision_geometry_wire_nodepth.vmat`,
`world_physics.vmdl`.

### 3.9. Protobuf / сеть

В строках присутствуют имена `.proto`-файлов Dota 2:

```
dota_broadcastmessages.proto   dota_clientmessages.proto   dota_commonmessages.proto
dota_gcmessages_common.proto   dota_shared_enums.proto     dota_usermessages.proto
google/protobuf/descriptor.proto
```

и **311** имён типов сообщений (`CDOTAUserMsg_*`, `CUserMsg_*`, `CMsg*`, `*Event`),
например `CMsgDOTACombatLogEntry`, `CDOTAUserMsg_ContextualTip`,
`CUserMsg_ParticleManager_t`, `AddModifierEvent`, `AddCriticalDamageEvent`.

Также найдены шаблоны `CNetMessagePB<size, MsgType, ...>` в RTTI — это классы-обёртки
конкретных сетевых сообщений; по параметрам шаблона виден и тип сообщения, и размер буфера.

### 3.10. Импорты (восстановлены косвенно)

`IMAGE_IMPORT_DESCRIPTOR` в файле отсутствует, но имена API-функций лежат в `.rdata`
(структуры `IMAGE_IMPORT_BY_NAME`). В `data/pe_info.json` → `readable_fragments` и в выводе
`dllkit.py pe` перечислены найденные имена. Упоминания в строках:

```
steam_api64.dll   host.dll   engine.dll   client.dll   pulse_system.dll
resourcecompiler.dll   tier0.dll   USER32.dll   GDI32.dll   WS2_32.dll
```

Характерная строка: `ERROR: CSource2Server::Connect - Failed to connect to saverestore
data in host.dll` и `Forcing S1 g_pNetworkStringTable to use version from engine.dll` —
подтверждает, что это серверный модуль Source 2, работающий в паре с `engine.dll`/`host.dll`,
с сохранением обратной совместимости с Source 1 (`S1 g_pNetworkStringTable`).

---

## 4. Методика (как воспроизведено)

Всё делается скриптами из `tools/`, без коммерческих инструментов.

| Шаг | Чем | Что на выходе |
|---|---|---|
| 1. Разбор PE | `tools/_pelib.py` (чистый Python, `struct`) | секции, каталоги, адреса |
| 1a. Экспорт/импорт | `PE.exports()` / `PE.imports()` + встроенный деманглер MSVC | `exports.ndjson`, `imports.ndjson` |
| 2. Границы функций | каталог `EXCEPTION` → `RUNTIME_FUNCTION[]` | `functions.tsv` |
| 3. Строки | regex `[\x20-\x7e]{4,}` и `(?:[\x20-\x7e]\x00){4,}` по образу | `symbols.ndjson`, `strings_full.txt` |
| 4. Классификация строк | 15 регулярных правил (`CATS` в `build_data.py`) | `index_categorized.txt` |
| 5. RTTI | поиск Type Descriptor'ов → COL (`signature==1`) → vtable | `rtti_types.txt`, `rtti_vtables.tsv` |
| 6. Дизассемблирование | capstone x86-64, `skipdata`, по границам из шага 2 | 776 421 RIP-ссылка |
| 7. xref | цель ссылки = `RVA_след_инструкции + disp32`; сопоставление с RVA строк и vtable | `function_strings.ndjson`, `string_functions.ndjson`, `function_classes.ndjson` |
| 8. Индексы | карта «ключ → байтовое смещение» для seek() | `_index/*.idx.json` |

Время полной пересборки: **~2 мин 20 с** на 2 vCPU (из них ~124 с — дизассемблирование
всех 244 974 функций), пиковая память ~700 МБ. Без xref (`--no-xref`) — **11 секунд**.

Деманглер MSVC (`demangle_msvc` в `tools/build_data.py`) — упрощённый: он не
восстанавливает полную сигнатуру (типы и порядок аргументов), но надёжно достаёт
имя сущности, цепочку классов, доступ (public/protected/private) и соглашение о вызове.
Для шаблонных имён (`?$CUtlVector@VCGenericBone@@...`) разбор параметров частичный —
это известное ограничение.

### Почему xref строится по функциям, а не линейным сканированием

Линейное сканирование `.text` байтовым поиском паттерна `REX.W 8D /r mod=00 rm=101` даёт
643 324 «кандидата», из которых на строки попадают лишь 120 — то есть почти всё это
случайные совпадения байтов внутри чужих инструкций и данных. Дизассемблирование
**от известных границ функций** (из `.pdata`) даёт 776 421 настоящую RIP-ссылку.
Разница в 6000 раз — именно поэтому в наборе есть `functions.tsv`.

---

## 5. Ограничения метода

1. **Нет имён функций.** 244 974 функции идентифицируются только RVA/размером/классом/строками.
   Там, где имя метода всё же встречается в строках (категория D, 1 996 имён), связь
   «имя → функция» устанавливается через xref, но не гарантированно: строка может
   использоваться функцией-обёрткой регистрации, а не самим методом.
2. **Класс определён только для 9.2 % функций.** Прочие — свободные функции, статические
   методы, шаблоны, inline-код и мелкие геттеры, которые не обращаются к vtable.
3. **xref ловит только RIP-относительные обращения.** Ссылки через абсолютный указатель в
   таблице (типично для protobuf-дескрипторов, схем данных, массивов описателей cvar)
   не попадают в `string_functions.ndjson`. Для них работает метод «соседства»:
   `dllkit.py near <file_off>` показывает, в каком массиве лежит строка.
4. **Строки короче 4 символов** и строки, не попавшие ни в одну категорию, есть только в
   `data/extras/strings_full.txt`.
5. **Дизассемблирование с `skipdata`** может неправильно разобрать функцию, если в её
   середине есть данные (таблицы переходов, выравнивание). Границы из `.pdata` при этом
   остаются верными.
6. **Хвостовые вызовы и объединённые функции** (COMDAT folding) могут дать одну запись
   `.pdata` на несколько логических функций.
7. **Версия.** Данные соответствуют SHA-256 `f7b7d300…`. После обновления Dota 2 адреса
   сместятся — нужно пересобрать `data/` (`tools/build_data.py --dll <новый файл>`),
   а `tools/get_dll.py --check` заранее сообщит, что версия другая.

---

## 6. Что можно сделать дальше (не входит в набор)

* **Декомпиляция в псевдокод.** Ghidra (бесплатно) или IDA Pro: загрузить `server.dll`,
  дождаться автоанализа (для 84 МБ — от нескольких часов), затем применить скрипт, который
  проставит имена функций из `function_strings.ndjson`/`function_classes.ndjson`.
  Это резко повысит читаемость псевдокода: у 72 946 функций появится смысловая привязка.
* **Импорт в Ghidra/IDA готовых данных.** Формат `.ndjson` тривиально конвертируется в
  скрипт установки bookmark'ов и имён (Ghidra: `setFunctionName`, IDA: `set_name`).
* **Восстановление схемы данных (Schema).** Строки `m_*` (8 977) и `CAttr_m_*` — это поля
  сетевой схемы Source 2; по соседству в `.data` лежат таблицы описателей полей
  (имя, смещение, тип, flags) — их можно разобрать и получить полную карту полей классов.
* **Protobuf-дескрипторы.** В бинарнике есть `google/protobuf/descriptor.proto` и имена
  сообщений; дескрипторы собраны в статических структурах, из которых восстанавливаются
  `.proto`-файлы целиком (поля, номера, типы).
* **Анализ конкретной подсистемы.** Например, для модификаторов: взять классы
  `CDOTA*Modifier*` из `rtti_types.txt` → их vtable из `rtti_vtables.tsv` → функции из
  `function_classes.ndjson` → строки из `function_strings.ndjson` → дизассемблирование.
