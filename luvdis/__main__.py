""" Luvdis CLI. """

import click
from click_default_group import DefaultGroup

from luvdis import __version__
from luvdis.config import read_config
from luvdis.common import eprint, set_debug
from luvdis.rom import ROM
from luvdis.analyze import State, BASE_ADDRESS, END_ADDRESS, THUMB, BYTE, WORD


class AddressInt(click.ParamType):
    name = "integer"

    def convert(self, value, param, ctx):
        try:
            if type(value) in (int, float):  # Passthrough defaults
                return value
            value = int(value, base=0)
            return min(max(value, BASE_ADDRESS), END_ADDRESS)
        except TypeError:
            self.fail(
                "expected string for int() conversion, got "
                f"{value!r} of type {type(value).__name__}",
                param,
                ctx,
            )
        except ValueError:
            self.fail(f"{value!r} is not a valid integer", param, ctx)


ADDRESS_INT = AddressInt()
MODE_MAP = {'byte': BYTE, 'thumb': THUMB, 'word': WORD}


@click.group(cls=DefaultGroup, default='disasm', default_if_no_args=True)
@click.version_option(message=f'Luvdis {__version__}')
def main():
    pass


@main.command('disasm')
@click.version_option(message=f'Luvdis {__version__}')
@click.argument('rom', type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option('-o', '--output', type=click.Path(writable=True, dir_okay=False, allow_dash=True), default='-',
              help='Disassembly output path. If configuration contains module information, this is only the initial '
                   'output path.')
@click.option('-c', '--config', type=click.Path(exists=True, dir_okay=False, readable=True),
              help='Function configuration file.')
@click.option('-co', '--config-out', type=click.Path(writable=True, dir_okay=False),
              help="Output configuration. If any functions are 'guessed' by Luvdis, they will appear here.")
@click.option('-D', '--debug', is_flag=True, help='Turn on/off debugging behavior.')
@click.option('--start', type=ADDRESS_INT, default=BASE_ADDRESS,
              help='Starting address to disassemble. Defaults to 0x8000000 (the start of the ROM).')
@click.option('--stop', type=ADDRESS_INT, default=float('inf'),
              help='Stop disassembly at this address. Defaults to infinity.')
@click.option('--macros', type=click.Path(exists=True, dir_okay=False, readable=True),
              help="Assembler macro file to '.include' in disassembly. If not specified, default macros are embedded.")
@click.option('--guess/--no-guess', default=True,
              help='Turn on/off function guessing & discovery. Default is to perform guessing.')
@click.option('--min-calls', type=click.IntRange(1), default=2,
              help="Minimum number of calls to a function required in order to 'guess' it. Must be at least 1, "
                   "defaults to 2.")
@click.option('--min-length', type=click.IntRange(1), default=3,
              help="Minimum valid instruction length required in order to 'guess' a function. Must be at least 1, "
                   "defaults to 3.")
@click.option('--default-mode', type=click.Choice(('THUMB', 'BYTE', 'WORD'), case_sensitive=False), default='BYTE',
              help="Default disassembly mode when the nature of an address is unknown. Defaults to 'BYTE'.")
def disasm(rom, output, config, config_out, debug, start, stop, macros, guess, min_calls, min_length, default_mode,
           **kw):
    """ Analyze and disassemble a GBA ROM. """
    for k, v in kw.items():
        print(k, v)
    set_debug(debug)
    functions = read_config(config) if config else None
    rom = ROM(rom)
    state = State(functions, min_calls, min_length, start, stop, macros)
    state.analyze_rom(rom, guess)
    if output in (None, '-'):
        output = None
        eprint(f'No output file specified. Printing to stdout.')
    state.dump(rom, output, config_out, default_mode=MODE_MAP[default_mode.lower()])


@main.command(name='info')
@click.version_option(message=f'Luvdis {__version__}')
@click.argument('rom', type=click.Path(exists=True, dir_okay=False, readable=True))
def info(rom):
    """ Detect GBA ROM game/database information. """
    rom = ROM(rom, detect=True)


if __name__ == '__main__':
    main()
