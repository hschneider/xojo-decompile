# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A single-file, dependency-free Python 3 tool (`xojo_decompile.py`) that decompiles a Xojo binary project (`.xojo_binary_project`, RbBF format) into text files close to the Xojo text project format. There are no tests, build step, linter config or packaging.

## Running

```sh
python xojo_decompile.py "path/to/Project.xojo_binary_project"
```

Output goes to `./<project name without suffix>` in the **current working directory** (not next to the input). It is also importable: `decompile(project, outdir=None)` returns the index list.

Output per item: `.xojo_code` (classes/modules/interfaces), `.xojo_window` + `.layout.json` (windows/containers), `.xojo_menu` (menu bars), plus a top-level `index.json`. Folders and modules become subdirectories.

## Architecture

The pipeline has three layers:

1. **Parsing** — `read_blocks()` walks `Blok` records starting at offset `0x1c`; each block's payload (at block + 32) is parsed by `parse_items()` into a tree of `Node`s (tag + 4-char type: `Strn`, `Int `, `Dbl `, `Rect`, `Grup`). Groups recurse until an `EndG` item; `Padn` ends the block. Encrypted blocks (flags == 2) have `node = None`. An unknown item type raises `ValueError` — extending the format usually means adding a branch in `parse_items()`.
2. **Rendering** — `render_class()`, `render_window()`, `render_menu()` turn a block's root `Node` into text. `render_members()` is shared by classes and window code and emits `#tag` sections for event handlers (`HIns`), methods (`Meth`), event definitions (`Hook`), properties (`Prop`, computed when `CPrg`/`CPrs` exist), constants (`Cnst`/`CIns`), enums, structures (`Strx`) and notes. The binary format stores source lines unindented; `indent_source()` re-indents them heuristically by keyword.
3. **Project assembly** — `decompile()` filters blocks to `BLOCK_KINDS`, classifies them with `item_kind()` (a `pObj` can be a class, module via `bCls 0`, interface via `bNtr 1`, or window if it has `Ctrl` children), resolves the folder/module chain via each item's `Cont` parent id, and writes files.

Key format details (more in the header comment at the top of the file, which is the authoritative reverse-engineering notes — keep it updated when learning new format facts):

- `Node.get(tag)` returns the decoded text/int for leaf nodes but the `Node` itself for groups; `Node.all(tag)` returns raw `Node`s.
- In windows, `Ctrl` entries and `CBhv` (control behaviour / event handler) entries are matched **by position index**, not by name.
- Member `flag` bits map to scope via `scope()`; meaning differs inside modules (`&h0` = Global, `&h1` = Public) vs classes (`&h0` = Public, `&h1` = Protected). `in_module` is threaded through rendering for this reason.
- Property values (`PDef`/`PVal`) of type `Color` are ints and are formatted as `&cRRGGBB` (Xojo text) or `#RRGGBB` (layout JSON).
- Supports Xojo 2019 (`pVew`, classic `Window`) through 2024 (`pDWn`, `DesktopWindow`).
