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
* **ROM detection**: Unsure if you have a good copy of a ROM? Luvdis can let you know!

### Contents

- [Installation](#installation)
   - [From PyPI](#from-pypi)
   - [From Releases](#from-releases)
   - [From latest source](#from-latest-source)
- [Usage](#usage)
  - [Options](#options)
  - [ROM detection](#rom-detection)


## Installation

### From PyPI
Luvdis requires Python 3.6 or later.

```sh
$ python3 -m pip install luvdis --user
```

### From Releases
Arbitrary stable releases can be downloaded from GitHub and installed:
```sh
$ python3 -m pip install <path-to-zip> --user
```

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

### Options

```
usage: luvdis [-h] [-o OUT] [-c CONFIG] [-co CONFIG_OUT] [-D]
              [--min_calls MIN_CALLS] [--min_length MIN_LENGTH]
              [--start START] [--stop STOP] [--macros MACROS] [--no_guess]
              rom

positional arguments:
  rom                   Path to GBA ROM to disassemble

optional arguments:
  -h, --help            show this help message and exit
  -o OUT                Disassembly output path
  -c CONFIG, --config CONFIG
                        Path to function configuration file
  -co CONFIG_OUT, --config_out CONFIG_OUT
                        Optional function configuration output
  -D, --debug           Set debugging flag. This may add or change behavior!
  --min_calls MIN_CALLS
                        Minimum number of calls required to consider a
                        potential function. Default 2.
  --min_length MIN_LENGTH
                        Minimum codepath length required to consider a
                        potential function. Default 3.
  --start START         Start address to disassemble. Default 0x8000000.
  --stop STOP           Stop address to disassemble. Default infinity.
  --macros MACROS       Optional path of macros to include. If omitted, embeds
                        macros into the output file(s).
  --no_guess            Disable function discovery & guessing entirely. Use
                        only functions provided via -c.
```

### ROM Detection
To display information about a ROM and check if its hash is in the database:
```
$ luvdis info unknown_rom.gba
ROM detected: 'Pocket Monsters - Ruby (Japan)' ✔
```
