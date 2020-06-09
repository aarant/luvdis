# Luvdis
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/luvdis?logo=python&style=for-the-badge)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/luvdis?logo=pypi&logoColor=yellow&style=for-the-badge)](https://pypi.org/project/Luvdis/)
[![GitHub](https://img.shields.io/github/license/arantonitis/luvdis?style=for-the-badge)](https://github.com/arantonitis/luvdis/blob/master/LICENSE)

A smart Pure-Python GBA (Game Boy Advance) disassembler.

Luvdis is a tool for disassembling GBA ROMs. Features include:
* **Configurable output**: Disassemble to `stdout`, a single file, or separate output into modules based on configuration.
* **Platform accuracy**: Other disassembly engines like Capstone recognize instructions that are not legal in ARMv4 on the GBA's processor. Luvdis' custom decoder & disassembler solves this problem by attempting to replicate hardware behavior as closely as possible and only supporting ARMv4.
* **Function discovery**: Detect likely THUMB functions and differentiate between code and data.
* **Matching output**: Even if something goes wrong and a label overlaps with data, etc, Luvdis' disassembled output should assemble identically to the original ROM.
* **ROM detection**: Unsure if you have a good copy of a ROM? Luvdis can let you know with `luvdis info`!

### Contents

- [Installation](#installation)
   - [From PyPI](#from-pypi)
   - [From Releases](#from-releases)
   - [From latest source](#from-latest-source)
- [Usage](#usage)
  - [FAQ](#faq)
  - [Options](#options)
  - [ROM detection](#rom-detection)


## Installation

### From PyPI
Luvdis requires Python 3.6 or later.

```sh
$ python3 -m pip install luvdis --user
```

### From Releases
Arbitrary stable [releases](https://github.com/arantonitis/luvdis/releases/latest) can be downloaded from GitHub and installed:
```sh
$ python3 -m pip install <path-to-zip> --user
```

For Windows users, prebuilt binaries are also available.

### From latest source
```sh
$ python3 -m pip install git+git://https://github.com/arantonitis/luvdis#egg=luvdis
```

## Usage
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
# '#' starts a comment line.
# Function names are not mandatory; unknown funcs are named sub_<ADDRESS> when output.
arm_func 0x80000D0
thumb_func 0x800024C AgbMain
# If 'thumb_func' or 'arm_func' is omitted, the type is assumed to be 'thumb_func'.
# A module path may also be provided. Each time a new module is encountered, output switches to that path.
# Omitting the module will continue outputting to the same path.
0x80003b0 main.s CallCallbacks
```

To disassemble only part of a ROM, say, up to the start of read-only data, provide start and stop addresses:
```sh
$ luvdis rom.gba --start 0x0800024C --stop 0x0x81b32b4 -o rom.s
```

### FAQ

#### How can I get rid of large blocks of raw bytes in the disassembly?

By default, Luvdis treats areas of a ROM that it can't determine are executable as byte data. You can change this behavior
with the `default_mode` option:

```sh
$ luvdis rom.gba --default_mode THUMB -o rom.s
```

### Options

```
Usage: luvdis disasm [OPTIONS] ROM

  Analyze and disassemble a GBA ROM.

Options:
  --version                   Show the version and exit.
  -o, --output FILE           Disassembly output path. If configuration
                              contains module information, this is only the
                              initial output path.
  -c, --config FILE           Function configuration file.

  -co, --config-out FILE      Output configuration. If any functions are
                              'guessed' by Luvdis, they will appear here.
  -D, --debug                 Turn on/off debugging behavior.
  --start INTEGER             Starting address to disassemble. Defaults to
                              0x8000000 (the start of the ROM).
  --stop INTEGER              Stop disassembly at this address. Defaults to
                              0x9000000 (maximum ROM address + 1).
  --macros FILE               Assembler macro file to '.include' in
                              disassembly. If not specified, default macros
                              are embedded.
  --guess / --no-guess        Turn on/off function guessing & discovery.
                              Default is to perform guessing.
  --min-calls INTEGER RANGE   Minimum number of calls to a function required
                              in order to 'guess' it. Must be at least 1,
                              defaults to 2.
  --min-length INTEGER RANGE  Minimum valid instruction length required in
                              order to 'guess' a function. Must be at least 1,
                              defaults to 3.
  --default-mode [THUMB|BYTE|WORD]
                              Default disassembly mode when the nature of
                              an address is unknown. Defaults to 'BYTE'.
  --help                      Show this message and exit.
```

### ROM Detection
To display information about a ROM and check if its hash is in the database:
```
$ luvdis info unknown_rom.gba
ROM detected: 'Pocket Monsters - Ruby (Japan)' ✔
```
