""" Luvdis CLI. """
import sys
import argparse

from luvdis import __doc__ as description
from luvdis.config import read_config
from luvdis.common import eprint, set_debug
from luvdis.rom import ROM
from luvdis.analyze import State, BASE_ADDRESS


def parse_int(n):
    return int(n, 0)


parser = argparse.ArgumentParser(prog='luvdis', formatter_class=argparse.RawDescriptionHelpFormatter,
                                 description=description)
parser.add_argument('rom', type=str,
                    help='Path to GBA ROM to disassemble')
parser.add_argument('-o', type=str, dest='out', default=None,
                    help='Disassembly output path')
parser.add_argument('-c', '--config', type=str, dest='config', default=None,
                    help='Path to function configuration file')
parser.add_argument('-co', '--config_out', type=str, dest='config_out', default=None,
                    help='Optional function configuration output')
parser.add_argument('-D', '--debug', action='store_true', dest='debug',
                    help='Set debugging flag. This may add or change behavior!')
parser.add_argument('--min_calls', type=int, default=2,
                    help='Minimum number of calls required to consider a potential function. Default 2.')
parser.add_argument('--min_length', type=int, default=3,
                    help='Minimum codepath length required to consider a potential function. Default 3.')
parser.add_argument('--start', type=parse_int, default=BASE_ADDRESS,
                    help='Start address to disassemble. Default 0x8000000.')
parser.add_argument('--stop', type=parse_int, default=float('inf'),
                    help='Stop address to disassemble. Default infinity.')
parser.add_argument('--macros', type=str, default=None,
                    help='Optional path of macros to include. If omitted, embeds macros into the output file(s).')
parser.add_argument('--no_guess', action='store_false', dest='guess',
                    help='Disable function discovery & guessing entirely. Use only functions provided via -c.')


def main(args=None):
    args = args if args else sys.argv[1:]
    parsed = parser.parse_args(args)
    set_debug(parsed.debug)
    functions = read_config(parsed.config) if parsed.config else None
    state = State(functions, parsed.min_calls, parsed.min_length, parsed.start, parsed.stop, parsed.macros)
    rom = ROM(parsed.rom)
    state.analyze_rom(rom, parsed.guess)
    if parsed.out is None:
        eprint(f'No output file specified. Printing to stdout.')
    state.dump(rom, parsed.out, parsed.config_out)


if __name__ == '__main__':
    main()
