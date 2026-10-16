# xojo-decompile

Decompiles a Xojo binary project (`.xojo_binary_project`, RbBF format) into
readable text files, close to the Xojo text project format.

Every project item (classes, modules, interfaces, windows, containers, menus)
is extracted. Folders and modules become subdirectories, as in a Xojo text
project.

**Rescues corrupted projects:** if Xojo can no longer open a damaged
project file, xojo-decompile still extracts everything that is readable
(see [Corrupted projects](#corrupted-projects)).

## Requirements

Python 3, standard library only. No installation needed.

## Usage

```sh
python xojo_decompile.py "path/to/My App.xojo_binary_project"
```

This writes to `./My App` (the project name without its suffix) in the
**current folder**, creating it if needed, and prints one line per item:
kind, name, super class and output path.

It can also be used from Python:

```python
from xojo_decompile import decompile

index = decompile('My App.xojo_binary_project', outdir='out')
```

## Output

| File | Contents |
| --- | --- |
| `<Name>.xojo_code` | Classes, modules and interfaces: properties, computed properties, constants, enums, structures, methods, event definitions, event handlers, notes |
| `<Name>.xojo_window` | Windows and containers: window properties, every control with its non-default properties, the window code, then the control event handlers |
| `<Name>.layout.json` | The control layout of a window as JSON (class, position, size, parent, panel index and the most useful properties) |
| `<Name>.xojo_menu` | Menu bars |
| `index.json` | Every item with kind, super class and path (plus `errors` for damaged items) |
| `errors.log` | Only for damaged projects: every problem found, by item |
| `<Name>.raw.txt` | Only for damaged items that cannot be rendered: raw dump of their data |

The output is meant for reading, searching and diffing. It follows the Xojo
text format closely but is not guaranteed to open in the Xojo IDE.

## Supported Xojo versions

- Binary projects (RbBF format) saved by Xojo 2019 up to Xojo 2025.
- Classic desktop UI (`Window`, `ContainerControl`), written as `#tag Window`.
- API 2 desktop UI introduced in Xojo 2021r3 (`DesktopWindow`,
  `DesktopContainer`), written as `#tag DesktopWindow` /
  `#tag DesktopContainer`.
- Other versions may work but are untested. Unknown item types are
  reported in `errors.log` like damaged data.

## Corrupted projects

A damaged `.xojo_binary_project` (disk error, interrupted save, failed sync,
truncated download) is decompiled as far as possible instead of aborting:

- **Broken file structure:** a damaged header, blocks with invalid sizes,
  garbage between blocks or a truncated file. Blocks are found by scanning
  for the next block header.
- **Damaged item data:** parsing resumes at the next readable item, also
  after inserted or missing bytes. Everything before and after the damage
  is kept.
- **Per member recovery:** methods, properties, controls and event handlers
  are rendered one by one. One that cannot be rendered is written as a
  comment with a raw dump of its data, the rest of the item stays intact.
  An item that cannot be rendered at all is written as `<Name>.raw.txt`.
- **Report:** damaged items get an `errors` list in `index.json`, and all
  problems are listed in `errors.log` in the output folder. The run ends
  with a summary:

  ```
  7 damaged item(s) recovered partially, see errors.log
  ```

Data that is physically missing (e.g. the end of a truncated file) cannot
be recovered, and damaged text inside source code is extracted as is.
Always check recovered code before using it.

## Limitations

- Encrypted items cannot be decompiled without their password. They are
  listed in `index.json` with kind `encrypted`.
- The binary format stores source code unindented; indentation is restored
  heuristically and may be off in unusual code.

## File format

The RbBF format is not documented by Xojo. Notes on the reverse-engineered
format are in the header comment of
[`xojo_decompile.py`](xojo_decompile.py).

## License

[MIT](LICENSE) © 2026 Harald Schneider - marketmix.com
