# -*- coding: utf-8 -*-
"""
build_index.py — строит data/_index.json: побайтовые оффсеты каждой записи NDJSON-файлов.

Зачем: файлы в data/ большие (function_strings.ndjson ~41 МБ). Вместо полного чтения
любой инструмент (или ИИ-агент) может сделать seek() прямо на нужную запись.

Создаёт:
  data/_index.json — манифест всех файлов: размер, кол-во записей, смещения ключей
  data/_index/*.idx — бинарные/текстовые индексы «ключ -> байтовый оффсет в NDJSON»

Использование:  python3 tools/build_index.py [--data путь/к/data]
"""
import os, sys, json, argparse, re

def key_of(rec, fname):
    """Ключ(и) записи. Возвращает список пар (суффикс_индекса, ключ).

    Индексы мультисловные: одной строке может соответствовать несколько записей
    (например, одинаковый текст в разных местах образа), поэтому значение — СПИСОК
    байтовых оффсетов.
    """
    if fname.startswith('function_strings'):  return [('', str(rec.get('function_id')))]
    if fname.startswith('function_classes'):  return [('', str(rec.get('function_id')))]
    if fname.startswith('string_functions'):
        # два индекса: по точному тексту и по смещению строки в файле
        return [('', rec.get('text')), ('_byoff', str(rec.get('target_off')))]
        # _byoff: смещение строки в файле -> запись (нужен для who-uses по RVA/оффсету)
    # symbols.ndjson не индексируется: его ищут подстрокой/регекспом (dllkit.py find),
    # а точный текст там неоднозначен (128 361 записей, много дублей)
    return []

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--data'); a = ap.parse_args()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data = a.data or os.path.join(root, 'data')
    idx_dir = os.path.join(data, '_index'); os.makedirs(idx_dir, exist_ok=True)
    manifest = {'files': {}}
    for fn in sorted(os.listdir(data)):
        p = os.path.join(data, fn)
        if not os.path.isfile(p): continue
        st = os.stat(p)
        entry = {'size_bytes': st.st_size}
        if fn.endswith(('.tsv', '.txt', '.csv')):
            with open(p, encoding='utf-8', errors='replace') as fh:
                n = sum(1 for _ in fh)
            entry['lines'] = n
            if fn.endswith('.tsv'):
                entry['records'] = max(0, n - 1)      # минус строка заголовка
            print(f'[=] {fn}: {n} строк')
        if fn.endswith('.ndjson'):
            offs = {}          # суффикс -> {ключ: [оффсеты]}
            n = 0
            with open(p, 'rb') as f:
                pos = 0
                for line in f:
                    if not line.strip(): pos += len(line); continue
                    try: rec = json.loads(line)
                    except Exception: pos += len(line); continue
                    for suf, k in key_of(rec, fn):
                        if k is None:
                            continue
                        d = offs.setdefault(suf, {})
                        d.setdefault(k, []).append(pos)
                    n += 1; pos += len(line)
            entry['records'] = n
            if offs:
                total = 0
                for suf, d in offs.items():
                    idxfn = fn.replace('.ndjson', '.idx.json') if not suf else fn.replace('.ndjson', suf + '.idx.json')
                    json.dump(d, open(os.path.join(idx_dir, idxfn), 'w', encoding='utf-8'))
                    entry['index_file' + suf] = f'_index/{idxfn}'
                    entry['indexed_keys' + suf] = len(d)
                    total += len(d)
                    print(f'[+] {fn}{suf}: {n} записей, ключей {len(d)} -> _index/{idxfn}')
            else:
                entry['index_file'] = None
                print(f'[=] {fn}: {n} записей, индекс не нужен (маленький файл — читать целиком)')
        manifest['files'][fn] = entry
    json.dump(manifest, open(os.path.join(data, '_index.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    print('[+] data/_index.json')
    return 0

if __name__ == '__main__':
    sys.exit(main())
