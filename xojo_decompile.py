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
# - Binary projects (`RbBF` format) saved by Xojo 2019 up to Xojo 2025.
# - Classic desktop UI (`Window` in `pVew` blocks, `ContainerControl`),
#   written as `#tag Window`.
# - API 2 desktop UI introduced in Xojo 2021r3 (`DesktopWindow`,
#   `DesktopContainer`; windows in `pDWn` blocks), written as
#   `#tag DesktopWindow` / `#tag DesktopContainer`.
# - Other Xojo versions may work but are untested; unknown item types are
#   reported in `errors.log` like damaged data.
#
# Encrypted items cannot be decompiled without their password; they are
# listed in `index.json` as `encrypted`.
#
# Corrupted projects:
#
# Damaged files are decompiled as far as possible instead of aborting:
#
# - Blocks with an invalid size, garbage between blocks, a damaged file
#   header or a truncated file: blocks are found by scanning for the next
#   `Blok` header.
# - Damaged items inside a block: parsing resumes at the next plausible
#   item header (also after inserted or missing bytes), keeping everything
#   that could be read.
# - Members, controls and event handlers are rendered one by one; one that
#   fails is written as a comment with a raw dump of its data. An item that
#   cannot be rendered at all is written as `<Name>.raw.txt`.
# - Damaged items get an `errors` list in `index.json`; all problems are
#   listed in `errors.log` in the output folder.
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
# (c)2026 Harald Schneider - marketmix.com | MIT License, see LICENSE

import json
import re
import struct
import sys
from pathlib import Path

VERSION = '1.0.0'

BLOCK_KINDS = {
    'pObj': 'class', 'pDWn': 'window', 'pVew': 'window', 'pMnu': 'menu',
    'pFol': 'folder', 'pFTy': 'filetypes', 'pMod': 'module', 'pInt': 'interface',
}
FLAG_ENCRYPTED = 2

# Fixed payload size after the 8-byte item header (Strn: just its length field)
ITEM_SIZES = {'Strn': 4, 'Int ': 4, 'Dbl ': 8, 'Rect': 16, 'Grup': 8}
MAX_DEPTH = 64
# Plausible headers, used to resynchronise after corrupted data
ITEM_HEAD = re.compile(rb'[\x20-\x7e]{4}(?:Strn|Int |Dbl |Rect|Grup|Padn)')
BLOCK_HEAD = re.compile(rb'Blok[\x20-\x7e]{4}')


class Node:
    """
    A parsed item of a block: tag, type and value.
    Groups (type Grup) hold a list of child Nodes as their value.
    """
    __slots__ = ('tag', 'typ', 'value')

    def __init__(self, tag, typ, value):
        """
        Create a node.

        :param tag: 4-char tag, e.g. 'Name' or 'srcl'
        :param typ: 4-char item type: 'Strn', 'Int ', 'Dbl ', 'Rect' or 'Grup'
        :param value: Decoded value: bytes, int, float, tuple of 4 ints, or list of Nodes for a group
        """
        self.tag, self.typ, self.value = tag, typ, value

    def is_group(self):
        """
        Check whether this node is a group.

        :return: True if the value is a list of child Nodes
        """
        return self.typ == 'Grup'

    def text(self):
        """
        Value of the node, with byte strings decoded as UTF-8.

        :return: str, int, float, tuple or list of Nodes
        """
        v = self.value
        if isinstance(v, bytes):
            return v.decode('utf-8', 'replace')
        return v

    # Helpers for group nodes
    def get(self, tag, default=None):
        """
        Value of the first child with the given tag.

        :param tag: 4-char tag to look for
        :param default: Returned if no child has this tag
        :return: Decoded value of the child, the child Node itself if it is a group, or default
        """
        for n in self.value:
            if n.tag == tag:
                return n.text() if not n.is_group() else n
        return default

    def all(self, tag):
        """
        All children with the given tag, in file order.

        :param tag: 4-char tag to look for
        :return: List of Nodes
        """
        return [n for n in self.value if n.tag == tag]


class Block:
    """
    A project item: block type, item id, flags and its data (a group Node).
    """
    __slots__ = ('btype', 'id', 'flags', 'node', 'errors')

    def __init__(self, btype, bid, flags, node, errors=None):
        """
        Create a block.

        :param btype: 4-char block type, e.g. 'pObj' or 'pDWn'
        :param bid: Item id, referenced by the Cont item of child items
        :param flags: Block flags (2 = encrypted)
        :param node: Parsed data as a group Node, None for an encrypted block
        :param errors: Problems found while parsing the block (list of str)
        """
        self.btype, self.id, self.flags, self.node = btype, bid, flags, node
        self.errors = errors or []

    @property
    def encrypted(self):
        """
        Check whether the block is password protected.
        Encrypted blocks have no parsed data.

        :return: Boolean
        """
        return self.flags == FLAG_ENCRYPTED


def resync(b, pos, end):
    """
    Find the next plausible item header after corrupted data.
    Searches byte by byte, so it also recovers when inserted or missing bytes
    have broken the 4-byte alignment of the items. A candidate only counts if
    the item after it starts with a plausible header too, which skips text
    like `As Rect` inside source code strings.

    :param b: File contents
    :param pos: Position to start searching at
    :param end: End of the block
    :return: Position of the next item header, or end if there is none
    """
    for m in ITEM_HEAD.finditer(b, pos, end):
        p = m.start()
        typ = b[p + 4:p + 8].decode('latin1')
        nxt = p + 8 + ITEM_SIZES.get(typ, 0)
        if typ == 'Strn' and nxt <= end:
            nxt += (struct.unpack('>I', b[nxt - 4:nxt])[0] + 3) & ~3
        if typ == 'Padn' or nxt == end or (nxt < end and ITEM_HEAD.match(b, nxt)):
            return p
    return end


def parse_items(b, pos, end, errors, depth=0):
    """
    Parse the tagged items of a block into a list of Nodes.
    Recurses into groups and stops at the `EndG` item closing the current
    group or at `Padn`. Corrupted data does not raise: the problem is
    appended to errors and parsing continues at the next plausible item
    header, keeping every item that could be read.

    :param b: File contents
    :param pos: Position of the first item
    :param end: End of the block
    :param errors: List the parse problems are appended to
    :param depth: Group nesting level (0 for the block itself)
    :return: Tuple (list of Nodes, position after the last item)
    """
    items = []
    while pos + 8 <= end:
        start = pos
        tag = b[pos:pos + 4].decode('latin1')
        typ = b[pos + 4:pos + 8].decode('latin1')
        pos += 8
        if typ in ('Padn', '\0\0\0\0'):
            if depth:
                errors.append(f'group not closed before the block end at {start:#x}')
            return items, end
        size = ITEM_SIZES.get(typ)
        if size is None:
            errors.append(f'unknown item type {typ!r} (tag {tag!r}) at {start:#x}')
            pos = resync(b, start + 4, end)
            continue
        if pos + size > end:
            errors.append(f'item {tag!r} at {start:#x} runs past the block end')
            return items, end
        if typ == 'Strn':
            n = struct.unpack('>I', b[pos:pos + 4])[0]
            pos += 4
            if pos + n > end:
                errors.append(f'string {tag!r} at {start:#x} has invalid length {n}')
                pos = resync(b, pos, end)
                continue
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
            if depth >= MAX_DEPTH:
                errors.append(f'groups nested too deeply at {start:#x}')
                return items, end
            kids, pos = parse_items(b, pos, end, errors, depth + 1)
            items.append(Node(tag, typ, kids))
        elif typ == 'Rect':
            items.append(Node(tag, typ, struct.unpack('>4i', b[pos:pos + 16])))
            pos += 16
        elif typ == 'Dbl ':
            items.append(Node(tag, typ, struct.unpack('>d', b[pos:pos + 8])[0]))
            pos += 8
    if depth:
        errors.append(f'group not closed before the block end at {end:#x}')
    return items, pos


def read_blocks(path, warnings=None):
    """
    Read every block of a .xojo_binary_project file, in file order.
    Damage to the file structure (bad header, invalid block sizes, garbage
    between blocks, missing end marker) is appended to warnings; blocks are
    then found by scanning for the next `Blok` header.

    :param path: Path of the .xojo_binary_project file
    :param warnings: List the file level problems are appended to
    :return: Generator of Blocks
    """
    warnings = [] if warnings is None else warnings
    b = Path(path).read_bytes()
    if b[:4] != b'RbBF':
        warnings.append('file header is not RbBF, scanning for blocks anyway')
    pos = 0x1c
    while pos < len(b):
        if b[pos:pos + 4] == b'EOF!':
            return
        if not BLOCK_HEAD.match(b, pos) or pos + 32 > len(b):
            m = BLOCK_HEAD.search(b, pos + 1)
            skip_to = m.start() if m else len(b)
            warnings.append(f'{skip_to - pos} bytes of unreadable data at {pos:#x} skipped')
            pos = skip_to
            continue
        btype = b[pos + 4:pos + 8].decode('latin1')
        bid, _, size, flags = struct.unpack('>iIII', b[pos + 8:pos + 24])
        errors = []
        end = pos + size
        if size < 32 or end > len(b) or (end < len(b) and b[end:end + 4] not in (b'Blok', b'EOF!')):
            m = BLOCK_HEAD.search(b, pos + 32)
            end = m.start() if m else len(b) - 4 if b.endswith(b'EOF!') else len(b)
            errors.append(f'invalid block size {size} at {pos:#x}, block assumed to end at {end:#x}')
        node = None
        if flags != FLAG_ENCRYPTED:
            node = Node('Blok', 'Grup', parse_items(b, pos + 32, end, errors)[0])
        yield Block(btype, bid, flags, node, errors)
        pos = end
    warnings.append('file ends without EOF! marker (truncated?)')


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def dump_lines(node, ind=''):
    """
    Plain text dump of a node tree.
    Fallback for data that cannot be rendered as Xojo code.

    :param node: Group Node to dump
    :param ind: Indentation of the first level
    :return: List of lines
    """
    lines = []
    for n in node.value:
        if n.is_group():
            lines.append(f'{ind}{n.tag} {{')
            lines.extend(dump_lines(n, ind + '  '))
            lines.append(f'{ind}}}')
        else:
            v = n.text()
            lines.append(f'{ind}{n.tag} = {json.dumps(v, ensure_ascii=False) if isinstance(v, str) else v}')
    return lines


def guarded(lines, items, render, what, ind='\t'):
    """
    Render items one by one, so a damaged item does not affect the others.
    An item that fails to render is written as a comment with a raw dump of
    its data instead, so nothing is lost.

    :param lines: List the rendered lines are appended to
    :param items: Nodes, or (index, Node) tuples, to render
    :param render: Function render(item, out) appending the lines of one item to out
    :param what: Name of the item kind, used in the error comment, e.g. 'Method'
    :param ind: Indentation of the error comment
    """
    for item in items:
        out = []
        try:
            render(item, out)
        except Exception as e:
            node = item[1] if isinstance(item, tuple) else item  # (index, node) pairs
            group = isinstance(node, Node) and node.is_group()
            name = (node.get('name') or node.get('Name')) if group else None
            out = [f'{ind}// {what} {name or ""}: could not be decompiled ({e!r}), raw data:']
            out += [f'{ind}// {s}' for s in dump_lines(node)] if group else []
            out.append('')
        lines.extend(out)


def source_lines(node, tag='sorc'):
    """
    Source lines of a member.

    :param node: Member Node (method, event, property, ...)
    :param tag: Group holding the lines: 'sorc', or 'CPrg' / 'CPrs' for the getter / setter of a computed property
    :return: List of source lines (str), empty if there is no source
    """
    sorc = node.get(tag)
    if sorc is None:
        return []
    return [n.text() for n in sorc.all('srcl')]


def indent_source(lines, base='\t\t'):
    """
    Re-indent Xojo source code.
    The binary format stores the lines unindented; the indentation is
    restored heuristically from the block keywords (If, For, Select, ...).

    :param lines: Source lines, the first one being the Sub/Function header and the last one its End line
    :param base: Indentation of the header and End line
    :return: List of indented lines
    """
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
    """
    Scope keyword for member flags.

    :param flag: Member flags, e.g. &h21 for Private
    :param in_module: True for members of a module, where &h0 means Global and &h1 Public
    :return: 'Private', 'Protected', 'Public' or 'Global'
    """
    flag = flag or 0
    if flag & 0x21 == 0x21:
        return 'Private'
    if flag & 0x1:
        return 'Public' if in_module else 'Protected'
    return 'Global' if in_module else 'Public'


def fmt_value(p):
    """
    Format a property value as in a Xojo text project.

    :param p: PDef Node of the property
    :return: Value as str: colors as &cRRGGBB, strings quoted, numbers and booleans as is
    """
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
    """
    Render every member of a class, module or window as #tag sections:
    event handlers, methods, event definitions, properties, constants,
    enums, structures and notes.

    :param obj: Block Node of the class, module or window
    :param lines: List the rendered lines are appended to
    :param in_module: True for module members (changes the scope names)
    """
    def head(tag, m, extra=''):
        """
        Opening #tag line of a member.

        :param tag: Section name, e.g. 'Method' or 'Property'
        :param m: Member Node
        :param extra: Text appended after the flags
        :return: Line with the flags and a scope comment
        """
        flag = m.get('flag', 0) or 0
        shared = ' Shared' if m.get('shrd') else ''
        return f'\t#tag {tag}, Flags = &h{flag:X}{extra}  // {scope(flag, in_module)}{shared}'

    def event(h, lines):
        """
        Render an event handler implemented by the class.

        :param h: HIns Node
        :param lines: List the rendered lines are appended to
        """
        lines.append(f'\t#tag Event')
        lines.extend(indent_source(source_lines(h)))
        lines.append(f'\t#tag EndEvent')
        lines.append('')

    def method(m, lines):
        """
        Render a method, or the source-less method declaration of an interface.

        :param m: Meth Node
        :param lines: List the rendered lines are appended to
        """
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

    def hook(h, lines):
        """
        Render an event definition (an event the class raises).

        :param h: Hook Node
        :param lines: List the rendered lines are appended to
        """
        lines.append(head('Hook', h))
        src = source_lines(h)
        if src:
            lines.extend('\t\t' + s for s in src)
        else:
            rslt = f' As {h.get("rslt")}' if h.get('rslt') else ''
            lines.append(f'\t\tEvent {h.get("name")}({h.get("parm") or ""}){rslt}')
        lines.append(f'\t#tag EndHook')
        lines.append('')

    def prop(p, lines):
        """
        Render a property, as a computed property if it has getter or setter source.

        :param p: Prop Node
        :param lines: List the rendered lines are appended to
        """
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

    def constant(c, lines):
        """
        Render a constant with its platform and language specific instances.

        :param c: Cnst Node
        :param lines: List the rendered lines are appended to
        """
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

    def enum(e, lines):
        """
        Render an enumeration and its values.

        :param e: Enum Node
        :param lines: List the rendered lines are appended to
        """
        lines.append(f'\t#tag Enum, Name = {e.get("name")}, Type = {e.get("type")}, '
                     f'Flags = &h{e.get("flag", 0) or 0:X}  // {scope(e.get("flag"), in_module)}')
        lines.extend('\t\t' + s for s in source_lines(e) if s)
        lines.append('\t#tag EndEnum')
        lines.append('')

    def structure(s, lines):
        """
        Render a structure and its fields.

        :param s: Strx Node
        :param lines: List the rendered lines are appended to
        """
        lines.append(f'\t#tag Structure, Name = {s.get("name")}, '
                     f'Flags = &h{s.get("flag", 0) or 0:X}  // {scope(s.get("flag"), in_module)}')
        lines.extend('\t\t' + x for x in source_lines(s) if x)
        lines.append('\t#tag EndStructure')
        lines.append('')

    def note(n, lines):
        """
        Render a note (free text documentation).

        :param n: Note Node
        :param lines: List the rendered lines are appended to
        """
        lines.append('\t#tag Note, Name = ' + str(n.get('name')))
        lines.extend(['\t\t' + s for s in source_lines(n)])
        lines.append('\t#tag EndNote')
        lines.append('')

    for tag, render, what in (('HIns', event, 'Event'), ('Meth', method, 'Method'),
                              ('Hook', hook, 'Event definition'), ('Prop', prop, 'Property'),
                              ('Cnst', constant, 'Constant'), ('Enum', enum, 'Enum'),
                              ('Strx', structure, 'Structure'), ('Note', note, 'Note')):
        guarded(lines, obj.all(tag), render, what)


def pdefs(node):
    """
    Property definitions of a window or control.

    :param node: Window or control Node
    :return: Dict of PDef Nodes by property name
    """
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
    """
    Property values of a control, for the layout JSON.

    :param ctrl: Ctrl Node
    :return: Dict of values by property name, colors as #RRGGBB
    """
    out = {}
    for name, p in pdefs(ctrl).items():
        v = p.get('PVal')
        if (p.get('type') or '').lower() == 'color' and isinstance(v, int):
            v = '#%06X' % (v & 0xFFFFFF)
        out[name] = v
    return out


def class_header(blk, kind, in_module):
    """
    Declaration lines of a class, module or interface.

    :param blk: Block Node of the item
    :param kind: 'class', 'module' or 'interface'
    :param in_module: True if the item is nested in a module
    :return: Tuple (keyword such as 'Class', list of lines: attributes, declaration, Inherits, Implements)
    """
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
    """
    Render a window or container.
    Controls and their event handlers (CBhv) are matched by position.

    :param blk: Block Node of the window
    :param in_module: True if the window is nested in a module
    :return: Tuple (.xojo_window text, layout as a list of dicts for the JSON file)
    """
    sup = blk.get('Supr') or 'Window'
    tag = {'DesktopWindow': 'DesktopWindow', 'DesktopContainer': 'DesktopContainer',
           'Window': 'Window', 'ContainerControl': 'Window'}.get(sup, 'Window')
    lines = [f'#tag {tag}', f'Begin {sup} {blk.get("Name")}']
    guarded(lines, sorted(blk.all('PDef'), key=lambda p: str(p.get('name'))),
            lambda p, out: out.append(f'   {p.get("name")} = {fmt_value(p)}'), 'Property', '   ')
    ctrls = blk.all('Ctrl')
    behaviours = blk.all('CBhv')
    layout = []

    def control(ic, lines):
        """
        Render a control with its non-default properties and add its layout entry.

        :param ic: Tuple (position of the control, Ctrl Node)
        :param lines: List the rendered lines are appended to
        """
        i, c = ic
        props = control_props(c)
        cname = props.get('Name') or c.get('name')
        lines.append(f'   Begin {c.get("ccls")} {cname}')
        for pname, p in sorted(pdefs(c).items(), key=lambda kv: str(kv[0])):
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

    def control_events(ib, lines):
        """
        Render the event handlers of one control.

        :param ib: Tuple (position of the control, CBhv Node)
        :param lines: List the rendered lines are appended to
        """
        i, beh = ib
        hins = beh.all('HIns')
        if not hins:
            return
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

    guarded(lines, enumerate(ctrls), control, 'Control', '   ')
    lines.append('End')
    lines.append(f'#tag End{tag}')
    lines.append('')
    _, header = class_header(blk, 'class', in_module)
    lines.extend('// ' + h for h in header[1:])  # Inherits/Implements, for reference
    lines.append('#tag WindowCode')
    render_members(blk, lines)
    lines.append('#tag EndWindowCode')
    lines.append('')
    guarded(lines, enumerate(behaviours), control_events, 'Control events', '')
    return '\n'.join(lines) + '\n', layout


def render_class(blk, kind, in_module=False):
    """
    Render a class, module or interface.

    :param blk: Block Node of the item
    :param kind: 'class', 'module' or 'interface'
    :param in_module: True if the item is nested in a module
    :return: .xojo_code text
    """
    word, header = class_header(blk, kind, in_module)
    lines = [f'#tag {word}'] + header
    render_members(blk, lines, in_module=kind == 'module')
    lines.append(f'End {word}')
    lines.append(f'#tag End{word}')
    return '\n'.join(lines) + '\n'


def render_menu(blk):
    """
    Render a menu bar.

    :param blk: Block Node of the menu bar
    :return: .xojo_menu text
    """
    lines = [f'#tag Menu', f'Begin Menu {blk.get("Name")}']

    def walk(node, ind):
        """
        Render the menu items below a node, recursing into submenus.

        :param node: Menu bar or menu item Node
        :param ind: Number of spaces to indent the items with
        """
        for it in node.all('MItm'):
            props = {p.get('name'): p.get('PVal') for p in it.all('PDef')}
            text = it.get('text') if it.get('text') is not None else props.get('Text', '')
            line = f'Begin {it.get("Supr") or "MenuItem"} {it.get("name")} Text = {json.dumps(text, ensure_ascii=False)}'
            if it.get('scut'):
                line += f' ShortcutKey = {json.dumps(it.get("scut"))}'
            lines.append(' ' * ind + line)
            walk(it, ind + 3)
            lines.append(' ' * ind + 'End')
    try:
        walk(blk, 3)
    except Exception as e:  # keep the items rendered so far
        lines.append(f'   // menu could not be fully decompiled ({e!r})')
    lines += ['End', '#tag EndMenu']
    return '\n'.join(lines) + '\n'


# --------------------------------------------------------------------------
# Project
# --------------------------------------------------------------------------

def item_kind(blk):
    """
    Kind of a project item, derived from the block type and its data.

    :param blk: Block
    :return: 'class', 'module', 'interface', 'window', 'menu', 'folder', 'filetypes' or None
    """
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
    """
    Make an item name safe for use as a file or folder name.

    :param name: Item name
    :return: Name with path separators and control characters replaced, at most 120 characters
    """
    name = re.sub(r'[\\/:*?"<>|\x00-\x1f]', '_', str(name)).strip()
    return name[:120] or '_'


def render_item(blk, kind, in_module, base):
    """
    Render one project item into its output files.

    :param blk: Block of the item
    :param kind: Item kind from item_kind()
    :param in_module: True if the item is nested in a module
    :param base: Output path of the item without file extension
    :return: List of tuples (path, text), the main file first
    """
    if kind == 'window':
        text, layout = render_window(blk.node, in_module)
        return [(base.with_name(base.name + '.xojo_window'), text),
                (base.with_name(base.name + '.layout.json'),
                 json.dumps(layout, indent=1, ensure_ascii=False, default=str))]
    if kind == 'menu':
        return [(base.with_name(base.name + '.xojo_menu'), render_menu(blk.node))]
    return [(base.with_name(base.name + '.xojo_code'), render_class(blk.node, kind, in_module))]


def decompile(project, outdir=None, warnings=None):
    """
    Decompile a binary project.
    Writes one file per item (two for windows) plus index.json. An item that
    cannot be rendered at all is written as a raw dump (`<Name>.raw.txt`).
    Problems are listed in `errors.log` in outdir.

    :param project: Path of the .xojo_binary_project file
    :param outdir: Output folder, default ./<project name>
    :param warnings: List the file level problems are appended to
    :return: Index: list of dicts with name, kind, super class, path and, for damaged items, errors
    """
    warnings = [] if warnings is None else warnings
    outdir = Path(outdir) if outdir else Path.cwd() / Path(project).stem
    outdir.mkdir(parents=True, exist_ok=True)
    blocks = [b for b in read_blocks(project, warnings) if b.btype in BLOCK_KINDS]
    by_id = {b.id: b for b in blocks}
    kinds = {}
    for b in blocks:
        try:
            kinds[b.id] = item_kind(b)
        except Exception as e:
            b.errors.append(f'kind unknown, treated as class ({e!r})')
            kinds[b.id] = 'class'

    def parents(blk):
        """
        Folders and modules containing an item.

        :param blk: Block of the item
        :return: List of Blocks, outermost first
        """
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

    index, used = [], set()
    for blk in blocks:
        kind = kinds[blk.id]
        if blk.encrypted:
            index.append({'name': f'#{blk.id:08x}', 'kind': 'encrypted', 'type': blk.btype,
                          'super': '', 'path': ''})
            continue
        name = blk.node.get('Name')
        if kind in (None, 'folder', 'filetypes') or not (name or blk.errors):
            continue
        name = str(name or f'#{blk.id:08x}')  # damaged items may have lost their name
        errors = blk.errors
        chain = parents(blk)
        folder = outdir.joinpath(*[safe_name(p.node.get('Name') or '_') for p in chain])
        base = folder / safe_name(name)
        n = 2
        while base in used:  # damaged ids or names can collide
            base = folder / f'{safe_name(name)}_{n}'
            n += 1
        used.add(base)
        in_module = any(kinds[p.id] == 'module' for p in chain)
        try:
            files = render_item(blk, kind, in_module, base)
        except Exception as e:
            errors.append(f'could not be rendered, raw data written instead ({e!r})')
            files = [(base.with_name(base.name + '.raw.txt'), '\n'.join(dump_lines(blk.node)) + '\n')]
        try:
            folder.mkdir(parents=True, exist_ok=True)
            for path, text in files:
                path.write_text(text, encoding='utf-8', errors='replace')
        except OSError as e:
            errors.append(f'could not be written ({e})')
        qualified = '.'.join([str(p.node.get('Name')) for p in chain if kinds[p.id] == 'module'] + [name])
        entry = {'name': qualified, 'kind': kind, 'super': str(blk.node.get('Supr') or ''),
                 'path': files[0][0].relative_to(outdir).as_posix()}
        if errors:
            entry['errors'] = errors
        index.append(entry)
    (outdir / 'index.json').write_text(json.dumps(index, indent=1, ensure_ascii=False), encoding='utf-8')
    log = warnings + [f'{i["path"]}: {e}' for i in index for e in i.get('errors', [])]
    if log:
        (outdir / 'errors.log').write_text('\n'.join(log) + '\n', encoding='utf-8')
    return index


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(f'xojo_decompile {VERSION}\nusage: xojo_decompile.py <project.xojo_binary_project>')
    warnings = []
    try:
        items = decompile(sys.argv[1], warnings=warnings)
    except OSError as e:
        sys.exit(f'error: {e}')
    for item in items:
        print(f"{item['kind']:10} {item['name']:36} {item['super']:28} {item['path']}")
    for w in warnings:
        print(f'warning: {w}', file=sys.stderr)
    encrypted = sum(i['kind'] == 'encrypted' for i in items)
    if encrypted:
        print(f'\n{encrypted} encrypted item(s) skipped (no password)', file=sys.stderr)
    damaged = sum('errors' in i for i in items)
    if damaged:
        print(f'{damaged} damaged item(s) recovered partially, see errors.log', file=sys.stderr)
    print(f'\n{len(items)} items written to {Path.cwd() / Path(sys.argv[1]).stem}', file=sys.stderr)
