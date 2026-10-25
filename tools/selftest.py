#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest.py — проверка целостности набора данных БЕЗ самого server.dll.

Гоняет тот же сценарий, которым будет пользоваться ИИ-агент, и сверяет числа
с эталоном (версия SHA-256 f7b7d300…). Если вы пересобрали data/ из другой
версии бинарника — тест упадёт на числах, это нормально: обновите EXPECTED.

41 проверка без --dll, 43 с --dll (добавляются SHA-256 и размер самого бинарника).
Зелёный прогон на эталонной версии: «Итого: 41 пройдено, 0 провалено».

Использование:
  python3 tools/selftest.py            # человекочитаемый отчёт
  python3 tools/selftest.py --json     # машиночитаемый
  python3 tools/selftest.py --dll ./server.dll   # дополнительно проверить хеш бинарника
"""
import os, sys, json, argparse, bisect, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from dllkit import data_dir, ndjson, get_record, load_functions_starts  # noqa: E402

EXPECTED = {
    'sha256': 'f7b7d300c9d32ddd07e9b211026288c8c017528938486414a0a01037981cc566',
    'size_bytes': 88194712,
    'functions': 244974,
    'symbols': 128361,
    'rtti_types': 18826,
    'vtables': 20566,
    'functions_with_class': 22489,
    'functions_with_strings': 51991,     # записей в function_strings.ndjson может быть больше
    'strings_with_functions': 51932,
}

# эталонный пример: загрузчик Lua-модификаторов
SAMPLE_RVA = 0x00bf03fd
SAMPLE_CLASS = '.?AVCDOTALuaModifierEntry@@'
SAMPLE_STRING = 'Error parsing lua modifier from string table!'

# второй эталон: строка лога CDOTAGameManager::SetupGameKeyValues (проверка пути по RVA)
SAMPLE2_STRING = '[%s](%s)CDOTAGameManager::SetupGameKeyValues took %f msecs'
SAMPLE2_RVA = 0x03b81f28          # RVA строки в .rdata
SAMPLE2_OFF = 0x03b80528          # то же смещение в файле (дельта .rdata = 0x1A00)
SAMPLE2_FN_ID = 133276


class Arg:
    def __init__(self, dd):
        self.data = dd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data'); ap.add_argument('--dll'); ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    dd = data_dir(a)
    res = []

    def check(name, got, want, fatal=False):
        ok = (got == want)
        res.append({'check': name, 'got': got, 'expected': want, 'ok': ok})
        return ok

    # 1) файлы на месте
    need = ['pe_info.json', 'functions.tsv', 'symbols.ndjson', 'function_strings.ndjson',
            'string_functions.ndjson', 'function_classes.ndjson', 'rtti_types.txt',
            'rtti_vtables.tsv', 'index_categorized.txt', '_index.json']
    missing = [f for f in need if not os.path.isfile(os.path.join(dd, f))]
    check('все обязательные файлы присутствуют', missing, [])
    if missing:
        report(res, a.json, dd); return 1

    info = json.load(open(os.path.join(dd, 'pe_info.json'), encoding='utf-8'))
    check('sha256 бинарника-источника', info['sha256'], EXPECTED['sha256'])
    check('размер бинарника-источника', info['size_bytes'], EXPECTED['size_bytes'])
    check('ImageBase', info['image_base'], '0x180000000')
    check('секций', len(info['sections']), 5)
    check('.text не упакован (энтропия < 7.2)',
          next(s['entropy'] for s in info['sections'] if s['name'] == '.text') < 7.2, True)
    check('EXPORT присутствует в файле',
          next(x['present_in_file'] for x in info['data_directories'] if x['name'] == 'EXPORT'), True)
    check('экспортов (точек входа движка)', len(info.get('exports', {}).get('entries', [])), 6)
    check('в экспорте есть CreateInterface',
          any(e['name'] == 'CreateInterface' for e in info.get('exports', {}).get('entries', [])), True)
    check('в экспорте есть InstallSchemaBindings',
          any(e['name'] == 'InstallSchemaBindings' for e in info.get('exports', {}).get('entries', [])), True)
    check('импортирующих DLL', info.get('imports', {}).get('num_dlls'), 7)
    check('импортируемых функций', info.get('imports', {}).get('num_functions'), 744)
    check('больше всего импортов из tier0.dll',
          max(info.get('imports', {}).get('dlls', []), key=lambda x: x['num_functions'])['name'], 'tier0.dll')
    check('CLR_RUNTIME пуст (это не .NET)',
          any(x['name'] == 'CLR_RUNTIME' for x in info['data_directories']), False)
    check('PDB найден', bool(info.get('pdb')), True)

    # 2) счётчики
    starts, ends, ids = load_functions_starts(dd)
    check('функций в .pdata', len(starts), EXPECTED['functions'])
    check('функции отсортированы по RVA', starts == sorted(starts), True)
    n_sym = sum(1 for _ in ndjson(os.path.join(dd, 'symbols.ndjson')))
    check('строк-символов', n_sym, EXPECTED['symbols'])
    n_rtti = sum(1 for l in open(os.path.join(dd, 'rtti_types.txt'), encoding='utf-8') if l.strip())
    check('RTTI-типов', n_rtti, EXPECTED['rtti_types'])
    n_vt = sum(1 for i, l in enumerate(open(os.path.join(dd, 'rtti_vtables.tsv'), encoding='utf-8')) if i)
    check('vtable->класс', n_vt, EXPECTED['vtables'])
    n_fn_tsv = sum(1 for i, l in enumerate(open(os.path.join(dd, 'functions.tsv'), encoding='utf-8')) if i)
    check('строк в functions.tsv', n_fn_tsv, EXPECTED['functions'])
    n_fc = sum(1 for _ in ndjson(os.path.join(dd, 'function_classes.ndjson')))
    check('функций с классом', n_fc, EXPECTED['functions_with_class'])
    n_sf = sum(1 for _ in ndjson(os.path.join(dd, 'string_functions.ndjson')))
    check('строк с привязкой к функциям', n_sf, EXPECTED['strings_with_functions'])
    n_fs = sum(1 for _ in ndjson(os.path.join(dd, 'function_strings.ndjson')))
    res.append({'check': 'записей в function_strings.ndjson', 'got': n_fs,
                'expected': f">= {EXPECTED['functions_with_strings']}",
                'ok': n_fs >= EXPECTED['functions_with_strings']})

    # 3) сквозной сценарий агента: строка -> функции -> профиль функции
    rec = get_record(dd, 'string_functions.ndjson', SAMPLE_STRING)
    check('who-uses: эталонная строка найдена', bool(rec), True)
    if rec:
        f0 = rec['functions'][0]
        check('who-uses: RVA функции совпадает', int(f0['begin_rva'], 16), SAMPLE_RVA)
        prof = get_record(dd, 'function_strings.ndjson', f0['id'])
        check('func: профиль найден по _index (seek)', bool(prof), True)
        if prof:
            check('func: класс определён', prof['classes'][0], SAMPLE_CLASS)
            texts = [s['text'] for s in prof['strings']]
            check('func: строки функции извлечены', len(texts) >= 5, True)
            check('func: у каждой строки есть code_rva',
                  all(s.get('code_rva') for s in prof['strings']), True)

    # 3b) адресная привязка строки и поиск по RVA / смещению в файле
    rec2 = get_record(dd, 'string_functions.ndjson', SAMPLE2_STRING)
    check('string_functions: запись найдена по точному тексту', bool(rec2), True)
    if rec2:
        check('string_functions: есть target_rva', rec2.get('target_rva'), f'0x{SAMPLE2_RVA:08x}')
        check('string_functions: есть target_off', rec2.get('target_off'), SAMPLE2_OFF)
        check('string_functions: функция совпадает с эталоном',
              rec2['functions'][0]['id'], SAMPLE2_FN_ID)
        from dllkit import rva_to_off, load_index
        check('rva_to_off: RVA -> смещение в файле', rva_to_off(dd, SAMPLE2_RVA), SAMPLE2_OFF)
        idx_off = load_index(dd, 'string_functions_byoff.idx.json') or {}
        check('_index byoff: ключ — десятичное target_off', str(SAMPLE2_OFF) in idx_off, True)
        idx_txt = load_index(dd, 'string_functions.idx.json') or {}
        check('_index text: ключи не повреждены (sort_keys)', SAMPLE2_STRING in idx_txt, True)
        check('_index text: значение — список оффсетов',
              isinstance(idx_txt.get(SAMPLE2_STRING), list), True)

    # 3c) сквозной вызов CLI: who-uses по RVA
    import subprocess
    try:
        out = subprocess.run([sys.executable, os.path.join(HERE, 'dllkit.py'),
                              '--data', dd, 'who-uses', f'0x{SAMPLE2_RVA:08x}', '--json'],
                             capture_output=True, text=True, timeout=180)
        js = json.loads(out.stdout)
        check('CLI who-uses по RVA: найдена строка', js['matches'], 1)
        check('CLI who-uses по RVA: функция совпадает',
              js['results'][0]['functions'][0]['function_id'], SAMPLE2_FN_ID)
    except Exception as e:
        check(f'CLI who-uses по RVA ({e.__class__.__name__})', False, True)

    # 4) бинарный поиск по адресу
    i = bisect.bisect_right(starts, SAMPLE_RVA + 0x50) - 1
    check('поиск функции по адресу внутри неё', starts[i] <= SAMPLE_RVA + 0x50 < ends[i], True)

    # 5) опционально: хеш самого файла
    if a.dll:
        if not os.path.isfile(a.dll):
            res.append({'check': f'файл {a.dll}', 'got': 'не найден', 'expected': 'существует', 'ok': False})
        else:
            h = hashlib.sha256()
            n = 0
            with open(a.dll, 'rb') as f:
                for b in iter(lambda: f.read(1 << 20), b''):
                    h.update(b); n += len(b)
            check('sha256 server.dll', h.hexdigest(), EXPECTED['sha256'])
            check('размер server.dll', n, EXPECTED['size_bytes'])

    return report(res, a.json, dd)


def report(res, as_json, dd):
    bad = [r for r in res if not r['ok']]
    if as_json:
        print(json.dumps({'data_dir': dd, 'passed': len(res) - len(bad), 'failed': len(bad),
                          'ok': not bad, 'checks': res}, ensure_ascii=False, indent=1))
    else:
        print(f'Проверка набора данных: {dd}')
        for r in res:
            print(f'  [{"OK " if r["ok"] else "FAIL"}] {r["check"]}: {r["got"]} '
                  f'(ожидается {r["expected"]})')
        print(f'\nИтого: {len(res)-len(bad)} пройдено, {len(bad)} провалено')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
