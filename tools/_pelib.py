# -*- coding: utf-8 -*-
"""
_pelib.py — минимальный парсер PE32+ без внешних зависимостей.
Используется всеми инструментами набора. Python 3.8+.
"""
import struct, hashlib, os, re

DDN = ['EXPORT','IMPORT','RESOURCE','EXCEPTION','SECURITY','BASERELOC','DEBUG','ARCHITECTURE',
       'GLOBALPTR','TLS','LOAD_CONFIG','BOUND_IMPORT','IAT','DELAY_IMPORT','CLR_RUNTIME','RESERVED']

class Section:
    __slots__ = ('name','va','vsize','raw','rawsize','chars','index')
    def __init__(self, index, name, va, vsize, raw, rawsize, chars):
        self.index, self.name, self.va, self.vsize = index, name, va, vsize
        self.raw, self.rawsize, self.chars = raw, rawsize, chars
    def contains_off(self, off):  return self.raw <= off < self.raw + self.rawsize
    def contains_rva(self, rva):   return self.va <= rva < self.va + min(self.vsize, self.rawsize)
    def off2rva(self, off):        return self.va + (off - self.raw)
    def rva2off(self, rva):        return self.raw + (rva - self.va)
    def __repr__(self):
        return f'<Section {self.name} va=0x{self.va:x} vsize=0x{self.vsize:x} raw=0x{self.raw:x} rawsize=0x{self.rawsize:x}>'

class PE:
    """Разобранный PE-файл (образ в памяти = file-mapped)."""
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        self.size = len(self.data)
        d = self.data
        if d[:2] != b'MZ':
            raise ValueError('не PE-файл: нет сигнатуры MZ')
        self.pe_off = struct.unpack_from('<I', d, 0x3c)[0]
        if d[self.pe_off:self.pe_off+4] != b'PE\0\0':
            raise ValueError('не PE-файл: нет сигнатуры PE')
        (self.machine, self.nsec, self.timestamp, self.ptr_sym, self.nsym,
         self.optsize, self.chars) = struct.unpack_from('<HHIIIHH', d, self.pe_off + 4)
        self.opt = self.pe_off + 24
        self.magic = struct.unpack_from('<H', d, self.opt)[0]
        self.pe32plus = (self.magic == 0x20b)
        self.image_base = struct.unpack_from('<Q' if self.pe32plus else '<I', d, self.opt + 24)[0]
        self.entry_rva = struct.unpack_from('<I', d, self.opt + 16)[0]
        self.subsystem = struct.unpack_from('<H', d, self.opt + 68)[0]
        self.dll_chars = struct.unpack_from('<H', d, self.opt + 70)[0]
        dd = self.opt + (112 if self.pe32plus else 96)
        self.dirs = {}
        for i, n in enumerate(DDN):
            rva, sz = struct.unpack_from('<II', d, dd + 8 * i)
            self.dirs[n] = (rva, sz)
        self.sections = []
        sec = self.opt + self.optsize
        for i in range(self.nsec):
            o = sec + 40 * i
            nm = d[o:o+8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ro = struct.unpack_from('<IIII', d, o + 8)
            ch = struct.unpack_from('<I', d, o + 36)[0]
            self.sections.append(Section(i, nm, va, vs, ro, rs, ch))

    # ---- преобразования адресов ----
    def section_of_off(self, off):
        for s in self.sections:
            if s.contains_off(off): return s
        return None
    def section_of_rva(self, rva):
        for s in self.sections:
            if s.contains_rva(rva): return s
        return None
    def off2rva(self, off):
        s = self.section_of_off(off)
        return s.off2rva(off) if s else None
    def rva2off(self, rva):
        """Строго: RVA должен попадать в данные, реально присутствующие в файле."""
        s = self.section_of_rva(rva)
        if not s: return None
        o = s.rva2off(rva)
        return o if 0 <= o < self.size else None
    def va2rva(self, va):   return va - self.image_base
    def rva2va(self, rva):  return self.image_base + rva

    def read_cstr(self, off, maxlen=1024):
        if off is None or not (0 <= off < self.size): return None
        e = self.data.find(b'\0', off, off + maxlen)
        if e < 0: return None
        b = self.data[off:e]
        try: return b.decode('utf-8')
        except UnicodeDecodeError: return b.decode('latin1')

    def sha256(self): return hashlib.sha256(self.data).hexdigest()
    def md5(self):    return hashlib.md5(self.data).hexdigest()

    # ---- таблицы ----
    def functions(self):
        """RUNTIME_FUNCTION[] из каталога EXCEPTION (.pdata) = границы всех функций.
        Возвращает список кортежей (begin_rva, end_rva, unwind_rva)."""
        rva, sz = self.dirs['EXCEPTION']
        off = self.rva2off(rva)
        if off is None: return []
        n = sz // 12
        out = []
        d = self.data
        for i in range(n):
            b, e, u = struct.unpack_from('<III', d, off + 12 * i)
            if e > b: out.append((b, e, u))
        return out

    def exports(self):
        """Таблица экспорта (IMAGE_EXPORT_DIRECTORY). None, если её нет в файле."""
        rva, sz = self.dirs['EXPORT']
        o = self.rva2off(rva)
        if o is None: return None
        (ch, ts, maj, mi, name_rva, obase, nfun, nnames,
         afunc, anames, aords) = struct.unpack_from('<IIHHIIIIIII', self.data, o)
        no, ao, oo = self.rva2off(anames), self.rva2off(afunc), self.rva2off(aords)
        if None in (no, ao, oo): return None
        entries = []
        for i in range(nnames):
            nr = struct.unpack_from('<I', self.data, no + 4 * i)[0]
            ordv = struct.unpack_from('<H', self.data, oo + 2 * i)[0]
            fr = struct.unpack_from('<I', self.data, ao + 4 * ordv)[0]
            fwd = (rva <= fr < rva + sz)
            entries.append((ordv + obase, self.read_cstr(self.rva2off(nr)), fr, fwd))
        return {'name': self.read_cstr(self.rva2off(name_rva)), 'ordinal_base': obase,
                'num_functions': nfun, 'num_names': nnames, 'timestamp': ts, 'entries': entries}

    def imports(self):
        """Таблица импорта (IMAGE_IMPORT_DESCRIPTOR[]). None, если её нет в файле."""
        rva, sz = self.dirs['IMPORT']
        o = self.rva2off(rva)
        if o is None: return None
        dlls = []
        while True:
            ilt, ts, fwd, name_rva, fiat = struct.unpack_from('<IIIII', self.data, o)
            if not (name_rva or ilt): break
            name = self.read_cstr(self.rva2off(name_rva))
            funcs = []
            t = self.rva2off(ilt or fiat)
            if t is not None:
                while True:
                    v = struct.unpack_from('<Q' if self.pe32plus else '<I', self.data, t)[0]
                    t += 8 if self.pe32plus else 4
                    if v == 0: break
                    hi = 1 << (63 if self.pe32plus else 31)
                    if v & hi:
                        funcs.append({'ordinal': v & 0xffff, 'name': None,
                                      'iat': f'Ord{v & 0xffff}'})
                    else:
                        ho = self.rva2off(v & 0x7fffffff)
                        funcs.append({'ordinal': None,
                                      'name': self.read_cstr(ho + 2) if ho else None,
                                      'hint': struct.unpack_from('<H', self.data, ho)[0] if ho else None})
            dlls.append({'name': name, 'num_functions': len(funcs), 'iat_rva': fiat,
                         'timestamp': ts, 'functions': funcs})
            o += 20
        return {'dlls': dlls}

    def pdb_info(self):
        """(pdb_path, guid_hex, age) из CodeView RSDS."""
        rva, sz = self.dirs['DEBUG']
        off = self.rva2off(rva)
        if off is None: return None
        # IMAGE_DEBUG_DIRECTORY: Characteristics(4) TimeDateStamp(4) MajorVersion(2)
        # MinorVersion(2) Type(4) SizeOfData(4) AddressOfRawData(4) PointerToRawData(4)
        chars, ts, vmaj, vmin, typ, szdata, araw, raw = struct.unpack_from('<IIHHIIII', self.data, off)
        if typ != 2 or not (0 <= raw < self.size): return None
        cv = self.data[raw:raw + szdata]
        if cv[:4] != b'RSDS': return None
        import uuid
        g = uuid.UUID(bytes_le=cv[4:20])
        age = struct.unpack_from('<I', cv, 20)[0]
        return (self.read_cstr(raw + 24), g.hex.upper(), age)

RE_ASCII = re.compile(rb'[\x20-\x7e]{4,}')
RE_WIDE  = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')

def iter_strings(pe, min_len=4, sections=None, wide=True):
    """Генератор (file_off, rva, section_name, kind, text) для всех строк образа."""
    d = pe.data
    for m in RE_ASCII.finditer(d):
        off = m.start()
        s = pe.section_of_off(off)
        if sections and (s.name if s else '-') not in sections: continue
        t = m.group().decode('latin1')
        if len(t) < min_len: continue
        yield off, (s.off2rva(off) if s else 0), (s.name if s else '-'), 'ascii', t
    if wide:
        for m in RE_WIDE.finditer(d):
            off = m.start()
            s = pe.section_of_off(off)
            if sections and (s.name if s else '-') not in sections: continue
            t = m.group().decode('utf-16-le')
            if len(t) < min_len: continue
            yield off, (s.off2rva(off) if s else 0), (s.name if s else '-'), 'wide', t

def find_dll(path=None):
    """Найти server.dll: аргумент -> текущая папка -> корень репозитория -> .."""
    if path: return path
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    for c in (os.path.join(root, 'server.dll'), os.path.join(os.getcwd(), 'server.dll'),
              os.path.join(os.path.dirname(root), 'server.dll'), 'server.dll'):
        if os.path.isfile(c): return c
    return 'server.dll'
