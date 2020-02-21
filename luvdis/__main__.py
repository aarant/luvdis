import sys
import argparse

from luvdis.disassemble import DEBUG, State, ROM, eprint, BASE_ADDRESS, read_config


def parse_int(n):
    return int(n, 0)


parser = argparse.ArgumentParser(prog='luvdis')
parser.add_argument('rom', type=str)
parser.add_argument('-o', type=str, dest='out', default=None, metavar='output')
parser.add_argument('-c', '--config', type=str, dest='config', default=None)
parser.add_argument('-D', '--debug', action='store_true', dest='debug')
parser.add_argument('--min_calls', type=int, default=2)
parser.add_argument('--min_length', type=int, default=3)
parser.add_argument('--start', type=parse_int, default=BASE_ADDRESS)
parser.add_argument('--stop', type=parse_int, default=float('inf'))
parser.add_argument('--macros', type=str, default=None)


def main(args=None):
    global DEBUG
    args = args if args else sys.argv[1:]
    parsed = parser.parse_args(args)
    DEBUG = parsed.debug
    if parsed.config:
        functions = {addr: name for addr, (name, _) in read_config(parsed.config).items()}
    else:
        functions = {0x0800024c: 'AgbMain', 0x08000604: 'HBlankIntr', 0x08000348: 'UpdateLinkAndCallCallbacks'}
        # functions = {0x08000348: 'UpdateLinkAndCallCallbacks'}
        # functions = {}
    state = State(functions, parsed.min_calls, parsed.min_length, parsed.start, parsed.stop, parsed.macros)
    rom = ROM(parsed.rom)
    if parsed.out is None:
        f = sys.stdout
        eprint(f'No output file specified. Printing to stdout.')
        state.disassemble(rom, f)
    else:
        with open(parsed.out, 'w', buffering=1) as f:
            state.disassemble(rom, f)


if __name__ == '__main__':
    main()
