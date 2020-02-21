# Luvdis
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/luvdis?style=for-the-badge)
![PyPI](https://img.shields.io/pypi/v/luvdis?style=for-the-badge)
![GitHub](https://img.shields.io/github/license/arantonitis/luvdis?style=for-the-badge)

A smart Pure-Python GBA (Game Boy Advance) disassembler.

Luvdis is a tool for disassembling GBA ROMs. Features include:
* **Configurable output**: Disassemble to `stdout`, a single file, or separate output into modules based on configuration.
* **Function discovery**: Detect likely THUMB functions and differentiate between code and data.
* **Matching output**: Even if something goes wrong and a label overlaps with data, etc, Luvdis' disassembled output should assemble identically to the original ROM.

## Installation

### From PyPI
Luvdis requires Python 3.6 or later.

```sh
$ python3 -m pip install luvdis --user
```

### From Releases
Arbitrary stable releases can be installed from GitHub and running:
```sh
$ python3 -m pip install <path-to-zip> --user
```

### From latest source
```sh
$ python3 -m pip install git+git://https://github.com/arantonitis/luvdis#egg=luvdis
```

### Usage
The simplest way to use Luvdis is to simply give it a ROM and output file:
```sh
$ luvdis <path-to-rom> -o rom.s
```

To assist in function discovery/labeling, a list of functions can be provided:
```sh
$ luvdis -c functions.cfg rom.gba -o rom.s
```

This list should have the following structure:
```
# '#' starts a comment line that is ignored
# Function names are not mandatory; unknown funcs are named sub_<ADDRESS> when output.
arm_func 0x80000D0
# Function names may be explicitly provided though.
thumb_func 0x800024C AgbMain
# If 'thumb_func' or 'arm_func' is omitted, the type is assumed to be 'thumb_func'.
# A module path may also be provided. Each time a new module is encountered, output switches to that path.
# Omitting the module will continue outputting to the same path.
0x80003b0 main.s CallCallbacks
```

To disassemble only part of a ROM, say, up to the start of read-only data:
```sh
$ luvdis rom.gba --start 0x0800024C --stop 0x0x81b32b4 -o rom.s
```
