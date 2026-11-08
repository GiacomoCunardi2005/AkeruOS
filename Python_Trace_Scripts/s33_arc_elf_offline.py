#!/usr/bin/env python3
"""Simulate one ELF32 LE ARC700 ET_REL object; never execute or write an image."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from s33_check_arc_relocations import relocated_word

MAX_IMAGE = 16 * 1024 * 1024  # Host experiment limit, not Nikon RAM capacity.


def require(condition, message):
    if not condition:
        raise ValueError(message)


def span(raw, offset, size):
    require(0 <= offset <= len(raw) and 0 <= size <= len(raw) - offset,
            'file range out of bounds')
    return raw[offset:offset+size]


def string(raw, offset):
    require(0 <= offset < len(raw), 'string offset out of bounds')
    end = raw.find(b'\0', offset)
    require(end >= 0, 'unterminated string')
    return raw[offset:end].decode('utf-8')


def load(raw, base, external=None):
    """Return JSON-compatible simulated sections, symbols and applied RELA records."""
    external = {} if external is None else external
    require(isinstance(base, int) and 0 <= base < 2**32, 'invalid synthetic base')
    require(all(isinstance(n, str) and isinstance(v, int) and 0 <= v < 2**32
                for n, v in external.items()), 'invalid external symbol')
    require(52 <= len(raw) <= MAX_IMAGE, 'invalid input size')
    require(raw[:7] == b'\x7fELF\x01\x01\x01', 'expected ELF32 little-endian v1')
    require(raw[7:9] == b'\0\0', 'unsupported OSABI')
    h = struct.unpack_from('<HHIIIIIHHHHHH', raw, 16)
    require(h[0] == 1 and h[1] == 93 and h[2] == 1, 'expected ARC ET_REL v1')
    require(h[6] == 0x403, 'expected ARC700 ABI v4 flags 0x403')
    require(h[3] == h[4] == h[8] == h[9] == 0 and h[7] == 52,
            'unsupported entry or program headers')
    require(h[10] == 40 and 0 < h[11] < 0xff00 and 0 < h[12] < h[11],
            'unsupported section header table')
    section_bytes = span(raw, h[5], h[11]*40)
    sections = []
    for fields in struct.iter_unpack('<10I', section_bytes):
        s = dict(zip(('nameoff', 'type', 'flags', 'addr', 'offset', 'size',
                      'link', 'info', 'align', 'entsize'), fields))
        require(not s['align'] or not s['align'] & (s['align']-1),
                'section alignment is not a power of two')
        require(s['type'] != 9, 'SHT_REL is unsupported; require SHT_RELA')
        if s['type'] != 8:
            s['filedata'] = span(raw, s['offset'], s['size'])
        sections.append(s)
    require(not any(struct.unpack_from('<10I', section_bytes)), 'invalid null section')
    names = sections[h[12]]
    require(names['type'] == 3, 'invalid section name table')
    for s in sections:
        s['name'] = string(names['filedata'], s['nameoff'])

    cursor, allocated = base, {}
    for i, s in enumerate(sections):
        if not s['flags'] & 2:
            continue
        require(s['type'] in (1, 8) and not s['flags'] & ~7,
                'unsupported allocated section type or flags')
        alignment = s['align'] or 1
        cursor = (cursor + alignment - 1) & -alignment
        require(cursor + s['size'] <= 2**32 and cursor + s['size'] - base <= MAX_IMAGE,
                'simulated image exceeds address space or host limit')
        s['address'] = cursor
        s['memory'] = bytearray(s['size']) if s['type'] == 8 else bytearray(s['filedata'])
        allocated[i] = s
        cursor += s['size']
    require(allocated, 'no allocated sections')

    tables = [i for i, s in enumerate(sections) if s['type'] == 2]
    require(len(tables) == 1, 'expected exactly one SYMTAB')
    table_index = tables[0]
    table = sections[table_index]
    require(table['entsize'] == 16 and table['size'] >= 16 and not table['size'] % 16,
            'invalid symbol table size')
    require(table['link'] < len(sections) and sections[table['link']]['type'] == 3,
            'invalid symbol string table')
    require(table['info'] <= table['size']//16, 'invalid local symbol boundary')
    symbols = []
    for i, fields in enumerate(struct.iter_unpack('<IIIBBH', table['filedata'])):
        nameoff, value, size, info, other, index = fields
        name = string(sections[table['link']]['filedata'], nameoff)
        binding, kind = info >> 4, info & 15
        require(binding in (0, 1) and kind in (0, 1, 2, 3, 4),
                'unsupported symbol binding or type')
        require((binding == 0) == (i < table['info']), 'invalid symbol binding order')
        resolved = None
        if i == 0:
            require(not any(fields), 'invalid null symbol')
            resolved = 0
        elif index == 0:
            require(name in external, f'unresolved symbol: {name}')
            resolved = external[name]
        elif index == 0xfff1:
            resolved = value
        else:
            require(0 < index < len(sections), 'unsupported or invalid symbol section')
            require(value <= sections[index]['size'] and size <= sections[index]['size']-value,
                    'symbol extent out of bounds')
            if index in allocated:
                resolved = allocated[index]['address'] + value
                require(resolved < 2**32, 'symbol exceeds address space')
        symbols.append(dict(index=i, name=name, binding=binding, value=resolved))

    relocations, written = [], {}
    for rel in sections:
        if rel['type'] != 4:
            continue
        require(rel['link'] == table_index and rel['info'] in allocated,
                'invalid RELA symbol table or target')
        require(rel['entsize'] == 12 and not rel['size'] % 12, 'invalid RELA size')
        target = allocated[rel['info']]
        for offset, info, addend in struct.iter_unpack('<IIi', rel['filedata']):
            index, kind = info >> 8, info & 255
            require(index < len(symbols), 'relocation symbol index out of bounds')
            require(offset <= target['size'] and 4 <= target['size'] - offset,
                    'relocation write out of bounds')
            require(symbols[index]['value'] is not None, 'relocation to nonallocated symbol')
            sites = written.setdefault(rel['info'], set())
            require(not sites.intersection(range(offset, offset+4)), 'overlapping relocations')
            place = target['address'] + offset
            data = relocated_word(kind, symbols[index]['value'], addend, place)
            target['memory'][offset:offset+4] = data
            sites.update(range(offset, offset+4))
            relocations.append(dict(section=target['name'], offset=offset, kind=kind,
                                    symbol=symbols[index]['name'], addend=addend,
                                    place=place, bytes=data.hex()))
    return dict(input_sha256=hashlib.sha256(raw).hexdigest(), base=base, end=cursor,
                sections=[dict(index=i, name=s['name'], address=s['address'],
                               alignment=s['align'] or 1, type=s['type'],
                               size=s['size'], bytes=s['memory'].hex())
                          for i, s in allocated.items()],
                symbols=symbols, relocations=relocations,
                limits='Host simulation only; no execution, Nikon memory allocation or cache operations.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('object', type=Path)
    parser.add_argument('--base', type=lambda value: int(value, 0), required=True,
                        help='synthetic address for host simulation')
    args = parser.parse_args()
    try:
        with args.object.open('rb') as stream:
            result = load(stream.read(MAX_IMAGE+1), args.base)
    except (OSError, ValueError) as error:
        parser.exit(1, f'ERROR: {error}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
