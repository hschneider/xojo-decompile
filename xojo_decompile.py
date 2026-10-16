# Xojo binary project decompiler (RbBF format).
#
# Extracts every project item (classes, modules, interfaces, windows,
# containers, menus) of a `.xojo_binary_project` into readable text files,
# close to the Xojo text project format. Folders and modules become
# subdirectories, as in a Xojo text project:
#
# - `<Name>.xojo_code` source of classes, modules and interfaces
#   (properties, computed properties, constants, enums, structures, methods,
#   event definitions, event handlers, notes)
# - `<Name>.xojo_window` windows and containers: window properties, every
#   control with its non-default properties, the window code, then the event
#   handlers of the controls
# - `<Name>.layout.json` the control layout of a window as JSON (class,
#   position, size, parent, panel index and the most useful properties)
# - `<Name>.xojo_menu` menu bars
# - `index.json` every item with kind, super class and path
#
# Supported Xojo versions:
#
# - Binary projects (`RbBF` format) saved by Xojo 2019 up to Xojo 2024.
# - Classic desktop UI (`Window` in `pVew` blocks, `ContainerControl`),
#   written as `#tag Window`.
# - API 2 desktop UI introduced in Xojo 2021r3 (`DesktopWindow`,
#   `DesktopContainer`; windows in `pDWn` blocks), written as
#   `#tag DesktopWindow` / `#tag DesktopContainer`.
# - Other Xojo versions may work but are untested; an unknown item type
#   stops the run with a `ValueError` naming the type and file offset.
#
# Encrypted items cannot be decompiled without their password; they are
# listed in `index.json` as `encrypted`.
#
# Usage::
#
#     python xojo_decompile.py "path/to/My App.xojo_binary_project"
#
# writes to `./My App` (the project name without its suffix, in the
# current folder), which is created if needed.
#
# File format notes (reverse engineered):
#
# - File header: `RbBF` + version, the first block starts at 0x1c, the file
#   ends with `EOF!`.
# - Block: `Blok` + 4-char block type + 4-byte item id + 4 bytes + 4-byte
#   block size (from the block start) + 4-byte flags (2 = encrypted) +
#   padding, data starts at block + 32.
# - Data is a sequence of tagged items: 4-char tag + 4-char type:
#   `Strn` (u32 length + bytes padded to 4), `Int ` (i32), `Dbl `
#   (f64), `Rect` (4 x i32), `Grup` (u32 size + u32 group id, children
#   until `EndG Int <group id>`). `Padn` ends the block data.
# - `Cont` is the id of the parent item (folder or module, 0 = project).
# - `pObj` items are classes; `bCls 0` marks a module, `bNtr 1` an
#   interface. `pDWn` (DesktopWindow) and `pVew` (classic Window) are
#   windows.
# - Member flags: `&h21` Private, `&h1` Protected (Public in a module),
#   `&h0` Public (Global in a module), `&h40` dynamic constant.
#
# (c) 2026 Harald Schneider - marketmix.com
# MIT License, see LICENSE

import json
import re
import struct
import sys
from pathlib import Path

BLOCK_KINDS = {
    'pObj': 'class', 'pDWn': 'window', 'pVew': 'window', 'pMnu': 'menu',
    'pFol': 'folder', 'pFTy': 'filetypes', 'pMod': 'module', 'pInt': 'interface',
}
FLAG_ENCRYPTED = 2


class Node:
    """A parsed item: tag, type and value (list of Nodes for groups)."""
    __slots__ = ('tag', 'typ', 'value')

    def __init__(self, tag, typ, value):
        self.tag, self.typ, self.value = tag, typ, value

    def is_group(self):
        return self.typ == 'Grup'

    def text(self):
        v = self.value
        if isinstance(v, bytes):
            return v.decode('utf-8', 'replace')
        return v

    # Helpers for group nodes
    def get(self, tag, default=None):
        for n in self.value:
            if n.tag == tag:
                return n.text() if not n.is_group() else n
        return default

    def all(self, tag):
        return [n for n in self.value if n.tag == tag]


class Block:
    """A project item: block type, item id, flags and its data (a group Node)."""
    __slots__ = ('btype', 'id', 'flags', 'node')

    def __init__(self, btype, bid, flags, node):
        self.btype, self.id, self.flags, self.node = btype, bid, flags, node

    @property
    def encrypted(self):
        return self.flags == FLAG_ENCRYPTED


def parse_items(b, pos, end):
    items = []
    while pos + 8 <= end:
        tag = b[pos:pos + 4].decode('latin1')
        typ = b[pos + 4:pos + 8].decode('latin1')
        pos += 8
        if typ == 'Strn':
            n = struct.unpack('>I', b[pos:pos + 4])[0]
            pos += 4
            items.append(Node(tag, typ, b[pos:pos + n]))
            pos += (n + 3) & ~3
        elif typ == 'Int ':
            v = struct.unpack('>i', b[pos:pos + 4])[0]
            pos += 4
            if tag == 'EndG':
                return items, pos
            items.append(Node(tag, typ, v))
        elif typ == 'Grup':
            pos += 8
            kids, pos = parse_items(b, pos, end)
            items.append(Node(tag, typ, kids))
        elif typ == 'Rect':
            items.append(Node(tag, typ, struct.unpack('>4i', b[pos:pos + 16])))
            pos += 16
        elif typ == 'Dbl ':
            items.append(Node(tag, typ, struct.unpack('>d', b[pos:pos + 8])[0]))
            pos += 8
        elif typ in ('Padn', '\0\0\0\0'):
            return items, end
        else:
            raise ValueError(f'unknown item type {typ!r} (tag {tag!r}) at {pos - 8:#x}')
    return items, pos


def read_blocks(path):
    b = Path(path).read_bytes()
    if b[:4] != b'RbBF':
        raise ValueError('not a Xojo binary project (RbBF)')
    pos = 0x1c
    while pos < len(b) and b[pos:pos + 4] == b'Blok':
        btype = b[pos + 4:pos + 8].decode('latin1')
        bid, _, size, flags = struct.unpack('>iIII', b[pos + 8:pos + 24])
        if flags == FLAG_ENCRYPTED:
            node = None
        else:
            try:
                node = Node('Blok', 'Grup', parse_items(b, pos + 32, pos + size)[0])
            except (ValueError, struct.error) as e:
                raise ValueError(f'block {btype} at {pos:#x}: {e}') from None
        yield Block(btype, bid, flags, node)
        pos += size


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def source_lines(node, tag='sorc'):
    """Source lines of a member (sorc group, or CPrg/CPrs of a computed property)."""
    sorc = node.get(tag)
    if sorc is None:
        return []
    return [n.text() for n in sorc.all('srcl')]


def indent_source(lines, base='\t\t'):
    """Re-indent Xojo source (the binary format stores the lines unindented)."""
    out, level = [], 0
    for i, raw in enumerate(lines):
        s = raw.strip()
        low = s.lower().split('//')[0].strip()
        if i == 0 or i == len(lines) - 1:  # Sub/Function header and End line
            out.append(base + s)
            continue
        closer = re.match(r'^(#?end\b|#endif\b|next\b|wend\b|loop\b)', low)
        middle = re.match(r'^(#?else\b|#?elseif\b|catch\b|finally\b|case\b)', low)
        opener = (re.match(r'^#?if\b', low) and low.endswith('then')) or \
            re.match(r'^(for\b|while\b|do\b|select case\b|try\b|#pragma\b(?!))', low)
        if closer:
            level = max(0, level - (2 if low.startswith('end select') else 1))
        cur = level - 1 if middle else level
        out.append((base + '\t' * (cur + 1) + s) if s else '')
        if opener:
            level += 1
        if low.startswith('select case'):
            level += 1
    return out


def scope(flag, in_module=False):
    flag = flag or 0
    if flag & 0x21 == 0x21:
        return 'Private'
    if flag & 0x1:
        return 'Public' if in_module else 'Protected'
    return 'Global' if in_module else 'Public'


def fmt_value(p):
    """Format a PDef value."""
    typ = (p.get('type') or '')
    val = p.get('PVal')
    if typ.lower() == 'color' and isinstance(val, int):
        return '&c%06X' % (val & 0xFFFFFF)
    if isinstance(val, str):
        if typ.lower() in ('boolean', 'integer', 'double', 'single', 'number'):
            return val
        return json.dumps(val, ensure_ascii=False)
    return str(val)


def render_members(obj, lines, in_module=False):
    def head(tag, m, extra=''):
        flag = m.get('flag', 0) or 0
        shared = ' Shared' if m.get('shrd') else ''
        return f'\t#tag {tag}, Flags = &h{flag:X}{extra}  // {scope(flag, in_module)}{shared}'

    for h in obj.all('HIns'):
        lines.append(f'\t#tag Event')
        lines.extend(indent_source(source_lines(h)))
        lines.append(f'\t#tag EndEvent')
        lines.append('')
    for m in obj.all('Meth'):
        lines.append(head('Method', m))
        src = source_lines(m)
        if src:
            lines.extend(indent_source(src))
        else:  # interface methods have no source
            kind = 'Function' if m.get('rslt') else 'Sub'
            rslt = f' As {m.get("rslt")}' if m.get('rslt') else ''
            lines.append(f'\t\t{kind} {m.get("name")}({m.get("parm") or ""}){rslt}')
            lines.append(f'\t\tEnd {kind}')
        lines.append(f'\t#tag EndMethod')
        lines.append('')
    for h in obj.all('Hook'):
        lines.append(head('Hook', h))
        src = source_lines(h)
        if src:
            lines.extend('\t\t' + s for s in src)
        else:
            rslt = f' As {h.get("rslt")}' if h.get('rslt') else ''
            lines.append(f'\t\tEvent {h.get("name")}({h.get("parm") or ""}){rslt}')
        lines.append(f'\t#tag EndHook')
        lines.append('')
    for p in obj.all('Prop'):
        getter, setter = source_lines(p, 'CPrg'), source_lines(p, 'CPrs')
        computed = getter or setter
        lines.append(head('ComputedProperty' if computed else 'Property', p))
        if getter:
            lines.append('\t\t#tag Getter')
            lines.extend(indent_source(getter, '\t\t\t'))
            lines.append('\t\t#tag EndGetter')
        if setter:
            lines.append('\t\t#tag Setter')
            lines.extend(indent_source(setter, '\t\t\t'))
            lines.append('\t\t#tag EndSetter')
        src = [s for s in source_lines(p) if s]
        lines.extend(['\t\t' + s for s in src] or [f'\t\t{p.get("decl")}'])
        lines.append(f'\t#tag End{"ComputedProperty" if computed else "Property"}')
        lines.append('')
    for c in obj.all('Cnst'):
        flag = c.get('flag', 0) or 0
        lines.append(f'\t#tag Constant, Name = {c.get("name")}, Type = {c.get("type")}, '
                     f'Dynamic = {bool(flag & 0x40)}, '
                     f'Default = {json.dumps(c.get("defn") or "", ensure_ascii=False)}, '
                     f'Scope = {scope(flag, in_module)}')
        for ci in c.all('CIns'):
            lines.append(f'\t\t#Tag Instance, Platform = {ci.get("pltf")}, Language = {ci.get("lang")}, '
                         f'Definition = {json.dumps(ci.get("defn") or "", ensure_ascii=False)}')
        lines.append('\t#tag EndConstant')
        lines.append('')
    for e in obj.all('Enum'):
        lines.append(f'\t#tag Enum, Name = {e.get("name")}, Type = {e.get("type")}, '
                     f'Flags = &h{e.get("flag", 0) or 0:X}  // {scope(e.get("flag"), in_module)}')
        lines.extend('\t\t' + s for s in source_lines(e) if s)
        lines.append('\t#tag EndEnum')
        lines.append('')
    for s in obj.all('Strx'):
        lines.append(f'\t#tag Structure, Name = {s.get("name")}, '
                     f'Flags = &h{s.get("flag", 0) or 0:X}  // {scope(s.get("flag"), in_module)}')
        lines.extend('\t\t' + x for x in source_lines(s) if x)
        lines.append('\t#tag EndStructure')
        lines.append('')
    for n in obj.all('Note'):
        lines.append('\t#tag Note, Name = ' + str(n.get('name')))
        lines.extend(['\t\t' + s for s in source_lines(n)])
        lines.append('\t#tag EndNote')
        lines.append('')


def pdefs(node):
    return {p.get('name'): p for p in node.all('PDef')}


LAYOUT_KEYS = ('Left', 'Top', 'Width', 'Height', 'InitialParent', 'PanelIndex',
               'TabPanelIndex', 'Index', 'Visible', 'Enabled', 'Caption', 'Text',
               'Hint', 'Tooltip', 'HelpTag', 'InitialValue', 'Value', 'ColumnCount',
               'ColumnWidths', 'HasHeader', 'HeadingIndex', 'Bold', 'FontSize',
               'TextSize', 'TextAlignment', 'ReadOnly', 'Password', 'Multiline',
               'Panels', 'SelectedPanelIndex', 'LockLeft', 'LockTop', 'LockRight',
               'LockBottom', 'TextColor', 'BackgroundColor', 'HasBackgroundColor',
               'Icon', 'Format', 'MaximumCharactersAllowed', 'Location')


def control_props(ctrl):
    out = {}
    for name, p in pdefs(ctrl).items():
        v = p.get('PVal')
        if (p.get('type') or '').lower() == 'color' and isinstance(v, int):
            v = '#%06X' % (v & 0xFFFFFF)
        out[name] = v
    return out


def class_header(blk, kind, in_module):
    """Attributes, scope and declaration line(s) of a class, module or interface."""
    word = {'module': 'Module', 'interface': 'Interface'}.get(kind, 'Class')
    lines = []
    if blk.get('Atrb'):
        lines.append(f'Attributes ( {blk.get("Atrb")} ) ')
    lines.append(f'{"Protected " if in_module else ""}{word} {blk.get("Name")}')
    if blk.get('Supr'):
        lines.append(f'Inherits {blk.get("Supr")}')
    intr = [i.text() for i in blk.all('Intr') if not i.is_group()]
    if intr:
        lines.append(f'Implements {", ".join(intr)}')
    return word, lines


def render_window(blk, in_module=False):
    sup = blk.get('Supr') or 'Window'
    tag = {'DesktopWindow': 'DesktopWindow', 'DesktopContainer': 'DesktopContainer',
           'Window': 'Window', 'ContainerControl': 'Window'}.get(sup, 'Window')
    lines = [f'#tag {tag}', f'Begin {sup} {blk.get("Name")}']
    for pname, p in sorted(pdefs(blk).items()):
        lines.append(f'   {pname} = {fmt_value(p)}')
    ctrls = blk.all('Ctrl')
    behaviours = blk.all('CBhv')
    layout = []
    for i, c in enumerate(ctrls):
        props = control_props(c)
        cname = props.get('Name') or c.get('name')
        lines.append(f'   Begin {c.get("ccls")} {cname}')
        for pname, p in sorted(pdefs(c).items()):
            if p.get('PVal') in ('', None):
                continue
            lines.append(f'      {pname} = {fmt_value(p)}')
        lines.append('   End')
        entry = {'name': cname, 'class': c.get('ccls')}
        entry.update({k: props[k] for k in LAYOUT_KEYS if k in props})
        entry['events'] = []
        if i < len(behaviours):
            entry['events'] = [h.get('name') for h in behaviours[i].all('HIns')]
        layout.append(entry)
    lines.append('End')
    lines.append(f'#tag End{tag}')
    lines.append('')
    _, header = class_header(blk, 'class', in_module)
    lines.extend('// ' + h for h in header[1:])  # Inherits/Implements, for reference
    lines.append('#tag WindowCode')
    render_members(blk, lines)
    lines.append('#tag EndWindowCode')
    lines.append('')
    for i, beh in enumerate(behaviours):
        hins = beh.all('HIns')
        if not hins:
            continue
        if i < len(ctrls):
            props = control_props(ctrls[i])
            cname = props.get('Name') or ctrls[i].get('name')
            idx = props.get('Index')
        else:
            cname, idx = beh.get('Supr'), None
        suffix = f'  // Index {idx}' if idx not in (None, -2147483648, '-2147483648') else ''
        lines.append(f'#tag Events {cname}{suffix}')
        for h in hins:
            lines.append('\t#tag Event')
            lines.extend(indent_source(source_lines(h)))
            lines.append('\t#tag EndEvent')
        lines.append('#tag EndEvents')
    return '\n'.join(lines) + '\n', layout


def render_class(blk, kind, in_module=False):
    word, header = class_header(blk, kind, in_module)
    lines = [f'#tag {word}'] + header
    render_members(blk, lines, in_module=kind == 'module')
    lines.append(f'End {word}')
    lines.append(f'#tag End{word}')
    return '\n'.join(lines) + '\n'


def render_menu(blk):
    lines = [f'#tag Menu', f'Begin Menu {blk.get("Name")}']

    def walk(node, ind):
        for it in node.all('MItm'):
            props = {p.get('name'): p.get('PVal') for p in it.all('PDef')}
            text = it.get('text') if it.get('text') is not None else props.get('Text', '')
            line = f'Begin {it.get("Supr") or "MenuItem"} {it.get("name")} Text = {json.dumps(text, ensure_ascii=False)}'
            if it.get('scut'):
                line += f' ShortcutKey = {json.dumps(it.get("scut"))}'
            lines.append(' ' * ind + line)
            walk(it, ind + 3)
            lines.append(' ' * ind + 'End')
    walk(blk, 3)
    lines += ['End', '#tag EndMenu']
    return '\n'.join(lines) + '\n'


# --------------------------------------------------------------------------
# Project
# --------------------------------------------------------------------------

def item_kind(blk):
    kind = BLOCK_KINDS.get(blk.btype)
    if kind == 'class' and not blk.encrypted:
        if blk.node.get('bNtr') == 1:
            return 'interface'
        if blk.node.get('bCls') == 0:
            return 'module'
        if blk.node.all('Ctrl'):  # e.g. a ContainerControl stored as a class
            return 'window'
    return kind


def safe_name(name):
    return re.sub(r'[\\/:*?"<>|\0]', '_', name).strip() or '_'


def decompile(project, outdir=None):
    outdir = Path(outdir) if outdir else Path.cwd() / Path(project).stem
    outdir.mkdir(parents=True, exist_ok=True)
    blocks = [b for b in read_blocks(project) if b.btype in BLOCK_KINDS]
    by_id = {b.id: b for b in blocks}
    kinds = {b.id: item_kind(b) for b in blocks}

    def parents(blk):
        """Folders and modules containing blk, outermost first."""
        chain, seen = [], set()
        cont = blk.node.get('Cont') if blk.node else None
        while cont and cont in by_id and cont not in seen:
            seen.add(cont)
            p = by_id[cont]
            if p.node is None:
                break
            chain.insert(0, p)
            cont = p.node.get('Cont')
        return chain

    index = []
    for blk in blocks:
        kind = kinds[blk.id]
        if blk.encrypted:
            index.append({'name': f'#{blk.id:08x}', 'kind': 'encrypted', 'type': blk.btype,
                          'super': '', 'path': ''})
            continue
        name = blk.node.get('Name')
        if not name or kind in (None, 'folder', 'filetypes'):
            continue
        chain = parents(blk)
        folder = outdir.joinpath(*[safe_name(p.node.get('Name') or '_') for p in chain])
        folder.mkdir(parents=True, exist_ok=True)
        in_module = any(kinds[p.id] == 'module' for p in chain)
        base = folder / safe_name(name)
        if kind == 'window':
            text, layout = render_window(blk.node, in_module)
            files = [(base.with_name(base.name + '.xojo_window'), text),
                     (base.with_name(base.name + '.layout.json'),
                      json.dumps(layout, indent=1, ensure_ascii=False))]
        elif kind == 'menu':
            files = [(base.with_name(base.name + '.xojo_menu'), render_menu(blk.node))]
        else:
            files = [(base.with_name(base.name + '.xojo_code'), render_class(blk.node, kind, in_module))]
        for path, text in files:
            path.write_text(text, encoding='utf-8')
        qualified = '.'.join([p.node.get('Name') for p in chain if kinds[p.id] == 'module'] + [name])
        index.append({'name': qualified, 'kind': kind, 'super': blk.node.get('Supr') or '',
                      'path': files[0][0].relative_to(outdir).as_posix()})
    (outdir / 'index.json').write_text(json.dumps(index, indent=1, ensure_ascii=False), encoding='utf-8')
    return index


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: xojo_decompile.py <project.xojo_binary_project>')
    items = decompile(sys.argv[1])
    for item in items:
        print(f"{item['kind']:10} {item['name']:36} {item['super']:28} {item['path']}")
    encrypted = sum(i['kind'] == 'encrypted' for i in items)
    if encrypted:
        print(f'\n{encrypted} encrypted item(s) skipped (no password)', file=sys.stderr)
    print(f'\n{len(items)} items written to {Path.cwd() / Path(sys.argv[1]).stem}', file=sys.stderr)
