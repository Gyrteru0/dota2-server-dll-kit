#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
get_dll.py — скачать server.dll и проверить его целостность.

Сам бинарник в репозиторий НЕ входит (это проприетарный код Valve, ~84 МБ).
Он нужен только для:
  * tools/dllkit.py bytes  — hex-дамп и дизассемблирование;
  * tools/build_data.py    — пересборка данных из другого/обновлённого бинарника.

Где взять:
  1) Из установленной Dota 2:  <Steam>/steamapps/common/dota 2 beta/game/bin/win64/server.dll
  2) По прямой ссылке (--url), например из Dropbox/Google Drive/собственного хостинга.

Использование:
  python3 tools/get_dll.py --url "https://..." --out ./server.dll
  python3 tools/get_dll.py --check ./server.dll
  python3 tools/get_dll.py --from-steam

Эталонные хеши файла, на котором собраны данные в data/:
  SHA-256  f7b7d300c9d32ddd07e9b211026288c8c017528938486414a0a01037981cc566
  MD5      6178027dd7ae966282cf36598e7e0408
  размер   88194712 байт
"""
import argparse, hashlib, os, sys, glob

REF_SHA256 = 'f7b7d300c9d32ddd07e9b211026288c8c017528938486414a0a01037981cc566'
REF_MD5 = '6178027dd7ae966282cf36598e7e0408'
REF_SIZE = 88194712
STEAM_GLOBS = [
    os.path.expanduser('~/.steam/steam/steamapps/common/dota 2 beta/game/bin/win64/server.dll'),
    os.path.expanduser('~/.local/share/Steam/steamapps/common/dota 2 beta/game/bin/win64/server.dll'),
    'C:/Program Files (x86)/Steam/steamapps/common/dota 2 beta/game/bin/win64/server.dll',
    'D:/Steam/steamapps/common/dota 2 beta/game/bin/win64/server.dll',
    'D:/SteamLibrary/steamapps/common/dota 2 beta/game/bin/win64/server.dll',
]


def hashes(path, limit=None):
    h1, h2, n = hashlib.sha256(), hashlib.md5(), 0
    with open(path, 'rb') as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            h1.update(b); h2.update(b); n += len(b)
            if limit and n >= limit:
                break
    return h1.hexdigest(), h2.hexdigest(), n


def check(path):
    if not os.path.isfile(path):
        print(f'файл не найден: {path}')
        return 1
    sha, md5, size = hashes(path)
    ok_sha = (sha == REF_SHA256); ok_size = (size == REF_SIZE)
    print(f'файл    : {path}')
    print(f'размер  : {size} байт   {"OK" if ok_size else "ОТЛИЧАЕТСЯ от эталона " + str(REF_SIZE)}')
    print(f'SHA-256 : {sha}   {"OK" if ok_sha else "ОТЛИЧАЕТСЯ"}')
    print(f'MD5     : {md5}')
    print(f'эталон  : {REF_SHA256}')
    if not ok_sha:
        print('\nВнимание: это ДРУГАЯ версия server.dll (например, более свежее обновление Dota 2).')
        print('Данные в data/ собраны с эталонной версии и могут не совпадать по адресам.')
        print('Пересоберите: python3 tools/build_data.py --dll "%s" && python3 tools/build_index.py' % path)
    return 0 if ok_sha else 3


def from_steam(out):
    cands = [p for p in STEAM_GLOBS if os.path.isfile(p)]
    cands += glob.glob(os.path.join(os.path.expanduser('~'), '**/dota 2 beta/game/bin/win64/server.dll'),
                       recursive=False)
    if not cands:
        print('Не нашёл установленную Dota 2 по типовым путям. Скопируйте server.dll вручную из:')
        print('  <Steam>/steamapps/common/dota 2 beta/game/bin/win64/server.dll')
        return 2
    print('Найдено:', cands[0])
    if os.path.abspath(cands[0]) != os.path.abspath(out):
        import shutil
        shutil.copyfile(cands[0], out)
        print(f'Скопировано в {out}')
    return check(out)


def download(url, out):
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (dllkit)'})
        with urllib.request.urlopen(req, timeout=60) as r, open(out, 'wb') as f:
            total = int(r.headers.get('Content-Length') or 0)
            done = 0
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                f.write(b); done += len(b)
                if total:
                    sys.stdout.write(f'\r  {done/1048576:.1f} / {total/1048576:.1f} МБ')
                else:
                    sys.stdout.write(f'\r  {done/1048576:.1f} МБ')
                sys.stdout.flush()
        print()
    except Exception as e:
        print(f'\nОшибка загрузки: {e}')
        print('Примечание: ссылка Dropbox Transfer (/t/...) отдаёт HTML-страницу, а не файл.')
        print('Нужна прямая ссылка на скачивание, либо скопируйте файл из установленной игры:')
        print('  python3 tools/get_dll.py --from-steam')
        return 2
    return check(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--url', help='прямая ссылка на server.dll')
    ap.add_argument('--out', default='server.dll', help='куда сохранить (по умолчанию ./server.dll)')
    ap.add_argument('--check', metavar='PATH', help='только проверить хеши файла')
    ap.add_argument('--from-steam', action='store_true', help='найти и скопировать из установленной Dota 2')
    a = ap.parse_args()
    if a.check:
        return check(a.check)
    if a.from_steam:
        return from_steam(a.out)
    if a.url:
        return download(a.url, a.out)
    ap.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
