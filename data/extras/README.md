# data/extras/ — тяжёлые дубликаты, в git НЕ коммитятся

Эта папка пустая в свежем клоне. Файлы в ней — дубликаты основных данных из `data/`
в других форматах; для стандартного сценария поиска функций они не нужны.

Пересоздать (потребуется сам `server.dll`, ~2 мин 20 с):

```bash
pip install -r requirements.txt
python3 tools/build_data.py --dll /путь/к/server.dll --full
python3 tools/build_index.py
```

| Файл | Размер | Что это |
|---|---|---|
| `strings_full.txt` | 62 МБ | дамп **всех** 743 734 строк образа, включая `.text`, `.pdata`, `.reloc` и область Authenticode-подписи. Строки из `.text` — в основном случайные совпадения байтов кода с печатными символами. Формат: `0x<file_off>  RVA=0x<rva>  VA=0x<va>  <секция> <ascii\|wide> len=<n>  \|<текст>\|` |
| `functions.ndjson` | 33 МБ | то же, что `data/functions.tsv`, в NDJSON (числа без `0x`) |
| `function_strings.tsv` | 17 МБ | плоская таблица: по строке на пару «функция — строка». Колонки: `function_id, begin_rva, end_rva, size, classes, code_rva, target_rva, file_off, section, kind, string` |
| `symbols.tsv` | 10 МБ | `data/symbols.ndjson` в TSV: `off, rva, va, section, kind, len, text` |

TSV/CSV удобны для pandas, Excel, ClickHouse и `awk`; NDJSON — для построчной обработки
и ИИ-агентов. Основными считаются файлы в `data/`.
