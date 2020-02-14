import sys
import re
import os.path
import argparse
from bisect import bisect_left, bisect_right
from io import BytesIO
from collections import defaultdict

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB
from capstone.arm import ARM_INS_BX, ARM_INS_BL, ARM_INS_B, ARM_INS_PUSH, ARM_INS_LDR, ARM_INS_POP, ARM_INS_ADD
from capstone.arm import ARM_INS_MOV, ARM_INS_BLX, ARM_INS_BXJ, ARM_INS_LDC, ARM_INS_LDC2, ARM_INS_ADR


DEBUG = True
__version__ = '0.1.0'


class ROM:
    def __init__(self, path):
        self.thumb_md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
        self.arm_md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        self.thumb_md.skipdata = True
        self.arm_md.skipdata = True
        with open(path, 'rb') as f:
            self.buffer = f.read()
            self.size = len(self.buffer)
            self.f = BytesIO(self.buffer)
        dprint(f'Loaded {os.path.basename(path)}')

    def read(self, addr, size=1):
        self.f.seek(addr & 0xffffff)
        b = self.f.read(size)
        return int.from_bytes(b, 'little', signed=False)

    def dist(self, addr=0x08000000, count=None):
        self.f.seek(addr & 0xffffff)
        if count is None:
            buffer = self.f.read()
            yield from self.thumb_md.disasm(buffer, addr)
        else:
            buffer = self.f.read(count*4)  # Each instruction *could* be up to 4 bytes
            yield from self.thumb_md.disasm(buffer, addr, count)


def left_gt(l, x):
    """ Finds the leftmost element in l > x via binary search.

    Args:
        l (list): (Sorted) list to search.
        x: Element to test.

    Returns:
        Either the leftmost element > x, or None if x is the greatest element
    """
    i = bisect_right(l, x)
    return l[i] if i != len(l) else None


def right_lt(l, x):
    """ Finds the rightmost element in l < x via binary search.

    Args:
        l (list): (Sorted) list to search.
        x: Element to test.

    Returns:
        Either the rightmost element < x, if None if x is the smallest element
    """
    i = bisect_left(l, x)
    return l[i-1] if i else None


def find_bounds(l, low, high):
    """ Yields ordered elements x from l such that low <= x < high.

    Args:
        l (list): (Sorted) list to search.
        low: Minimum value to yield.
        high: Value to stop before.
    """
    i = bisect_left(l, low)
    if i == len(l):
        yield from []
    for j in range(i, len(l)):
        if l[j] >= high:
            break
        yield l[j]


def eprint(*args, **kwargs):  # Print to stderr
    return print(*args, file=sys.stderr, **kwargs)


def warn(s):
    return eprint('Warning:', s)


def dprint(*args, **kwargs):  # Print to stderr if debugging
    if DEBUG:
        return print(*args, file=sys.stderr, **kwargs)


FLAG_EXEC = 1
FLAG_WORD = 2


class AddrFlags:  # Markable address flags
    def __init__(self, size):
        self.size = size
        self.flags = bytearray(size)

    def __setitem__(self, item, flags):
        if type(item) is int:
            addr = item & 0xffffff
            self.flags[addr] = flags
        elif type(item) is slice:
            start, stop, step = item.start, item.stop, item.step
            if start is None:
                start = 0
            if stop is None:
                stop = self.size
            if step is None:
                step = 1
            start &= 0xffffff
            stop &= 0xffffff
            step &= 0xffffff
            for addr in range(start, min(stop, self.size), step):
                self.flags[addr] = flags
        else:  # Capstone instruction
            ins = item
            n = 4 if ins.id == ARM_INS_BL else 2
            base = ins.address & 0xffffff
            for addr in range(base, min(base+n, self.size)):
                self.flags[addr] = flags

    def __getitem__(self, item):
        if type(item) is int:
            addr = item & 0xffffff
            return self.flags[addr]
        elif type(item) is slice:
            start, stop, step = item.start, item.stop, item.step
            if start is None:
                start = 0
            if stop is None:
                stop = self.size
            if step is None:
                step = 1
            start &= 0xffffff
            stop &= 0xffffff
            step &= 0xffffff
            flags = 0
            for addr in range(start, min(stop, self.size), step):
                flags |= self.flags[addr]
            return flags
        else:
            ins = item
            base = ins.address & 0xffffff
            n = 4 if ins.id == ARM_INS_BL else 2
            return self[base:base+n]


FUNC = 0
BRANCH = 1
BYTE = 2
WORD = 3

THUMB = 0

BASE_ADDRESS = 0x08000000
load_re = re.compile(r'.*\[pc, #(0x[a-fA-F0-9]+)\]')
ASM_PRELUDE = f'@ Generated with Luvdis v{__version__}\n.syntax unified\n.text\n'
with open('function.inc', 'r') as f:
    MACROS = f.read()
INF = float('inf')
INVALID_IDS = {0, ARM_INS_LDC, ARM_INS_LDC2}


class State:
    def __init__(self, functions=None, min_calls=2, min_length=3, limit=INF, macros=None):
        self.unexpanded = functions.copy() if functions else {}  # Maps addr -> function name or None
        self.functions = {}  # addr -> (name, end)
        self.min_calls, self.min_length, self.limit = min_calls, min_length, limit
        self.macros = macros

        self.call_to = defaultdict(set)  # addr -> {called from}
        self.branch_links = []  # Sorted list of BL instructions
        self.branch_to = defaultdict(set)  # addr -> {branched from}
        self.branches = []  # Sorted list of branch addresses
        self.data = []  # Sorted list of non-coding instructions
        self.bxs = []  # Sorted list of BXs
        self.loads = []  # Sorted list of LDRs

        self.forks = []  # Sorted list of instructions that *guarantee* nonlinear execution

        self._to_sort = (self.branch_links, self.data, self.branches, self.bxs, self.loads, self.forks)

        self.flags = None
        self.label_map = {BASE_ADDRESS: BRANCH}

    def analyze_rom(self, rom):  # Analyze a ROM
        pushes = set()  # Set of push {xx, lr} instruction locations
        self.flags = AddrFlags(rom.size)
        # Build instruction tables, etc for later
        # for ins in rom.dist(BASE_ADDRESS):
        for ins in rom.dist(0x0800024C):  # TODO: Debug
            addr = ins.address
            if addr >= self.limit:
                break
            debug = False  # TODO: Debug
            if 0x08000D9C <= addr < 0x08000DA4:
                debug = False
            # THUMB.5
            if ins.id == ARM_INS_BX:
                self.bxs.append(addr)
            elif ins.id in (ARM_INS_ADD, ARM_INS_MOV) and ins.op_str[:2] == 'pc':
                self.forks.append(addr)
            # THUMB.6
            elif ins.id == ARM_INS_LDR:  # TODO: ldrh?
                m = load_re.match(ins.op_str)
                if m:
                    target = ((addr+4) & (~2)) + int(m.group(1), base=16)
                    if DEBUG and addr == 0x08000DA0:
                        dprint(f'DEBUG: {addr:08X}: ldr {target:08X}')
                    self.loads.append((addr, target))
            # TODO: THUMB.12 adr?
            # THUMB.14
            elif ins.id == ARM_INS_PUSH and 'lr' in ins.op_str:
                # Add addr and preceding locations as possible function entries
                pushes.add(max(BASE_ADDRESS, addr-4))
                pushes.add(max(BASE_ADDRESS, addr-2))
                pushes.add(addr)
            elif ins.id == ARM_INS_POP and 'pc' in ins.op_str:  # `pop {pc}`, though rare, is nonlinear
                self.forks.append(addr)
            # TODO: THUMB.15??
            # THUMB.16, THUMB.18
            elif ins.id == ARM_INS_B:
                target = int(ins.op_str[1:], base=16)
                self.branch_to[target].add(addr)
                self.branches.append(addr)
            # THUMB.19
            elif ins.id == ARM_INS_BL:
                target = int(ins.op_str[1:], base=16)
                self.call_to[target].add(addr)
                self.branch_links.append(addr)
            # Illegal instructions TODO: Are SWIs parsed?
            elif ins.id in INVALID_IDS:  # Non-coding instruction
                self.data.append(addr)
            if debug:
                input(f'{ins.address:08x} {ins.mnemonic} {ins.op_str}')
        # Merge forks with bxs
        self.forks.extend(self.bxs)
        for to_sort in self._to_sort:  # Sort all sorted lists
            to_sort.sort()
        # Intersect call destination and entry sets and add possible functions
        self.guess_funcs(rom, pushes)
        eprint(f'Found {len(self.unexpanded)} functions')
        # Repeatedly expand known functions until there are no changes
        changed = True
        while changed:
            changed = self.expand_funcs(rom)
            eprint(f'Found {len(self.functions)} functions')
        self.make_labels(rom)

    def guess_funcs(self, rom, entries):  # Guess functions based on heuristic
        for maybe_func in entries:
            if maybe_func not in self.unexpanded and maybe_func < self.limit:
                ncalls = len(self.call_to[maybe_func])  # Number of calls pointing here
                if ncalls < self.min_calls:  # Not enough calls; reject
                    continue
                # Only accept functions with at least min_length legal instructions
                if any(ins.id == 0 for ins in rom.dist(maybe_func, self.min_length)):
                    continue
                if maybe_func > 0x081B32B0:
                    dprint(f'DEBUG: Func {maybe_func:08X} added')
                self.unexpanded[maybe_func] = None  # Accept the function

    def expand_func(self, rom, addr):  # Expands function codepaths and marks memory regions
        starts = {addr}
        expanded = set()
        exit_addr = addr  # Highest address beyond executable code in the function
        calls = set()  # Set of addresses called with BL
        while starts:
            new_starts = set()
            for start in starts:
                data = left_gt(self.data, start)  # First non-coding instr
                fork = left_gt(self.forks, start)  # First fork
                data = data if data else rom.size | 0x08000000
                fork = fork + 2 if fork else rom.size | 0x08000000
                end = min(data, fork)
                for b in find_bounds(self.branches, start, end):  # Simulate each branch
                    ins, = rom.dist(b, 1)
                    target = int(ins.op_str[1:], base=16)
                    if target < self.limit:
                        self.label_map[target] = BRANCH  # Mark as branch
                        if target not in expanded:  # Add target as a potential start run
                            if target > 0x081B32B0:
                                dprint(f'DEBUG: Target {target:08X} reached at {b:08X}: {ins.mnemonic} {ins.op_str}')
                            new_starts.add(target)
                    if ins.mnemonic == 'b':  # Unconditional branch; stop execution
                        end = min(end, b+2)
                        break
                for bl in find_bounds(self.branch_links, start, end):  # Look at each BL
                    ins, = rom.dist(bl, 1)
                    target = int(ins.op_str[1:], base=16)
                    if target < self.limit:
                        self.label_map[target] = BRANCH
                        calls.add(target)
                # Mark the whole region from start:end as executable
                self.flags[start:end] |= FLAG_EXEC
                # Mark each load target as readable  TODO
                ninf = -float('inf')
                for ld, target in find_bounds(self.loads, (start, ninf), (end, ninf)):
                    if target < self.limit:
                        self.label_map[target] = WORD
                        self.flags[target:target+4] |= FLAG_WORD
                # Take the max of the exit address and the end of this run
                exit_addr = max(exit_addr, end)
                expanded.add(start)
            starts = new_starts
        return exit_addr, calls

    def expand_funcs(self, rom):
        changed = False
        for func, name in self.unexpanded.copy().items():
            end, calls = self.expand_func(rom, func)
            for target in calls:
                if target not in self.functions and target not in self.unexpanded:
                    if target > 0x081B32B0:
                        dprint(f'DEBUG: Target {target:08X} called from func {func:08X}')
                    self.unexpanded[target] = None
                    changed = True
            self.functions[func] = (name, end)
            self.unexpanded.pop(func)
        return changed

    def __str__(self):
        return f'{len(self.functions)}:{len(self.unexpanded)} c:{self.min_calls} l:{self.min_length}'

    def make_labels(self, rom):  # Generate labels
        for func in self.functions:
            self.label_map[func] = FUNC
        self.labels = list(self.label_map.keys())
        self.labels.sort()

    def label_for(self, addr):
        if addr in self.label_map:
            if self.label_map[addr] == FUNC:
                name, _ = self.functions[addr]
                if name is None:
                    name = f'sub_{addr:08X}'
                return name
        return f'_{addr:08X}'

    def dump(self, rom, f):
        if True:
            addr_map = {addr: (name, None) for addr, (name, _) in self.functions.items()}
            write_config(addr_map, 'luvdis.cfg')
        f.write(ASM_PRELUDE)
        if self.macros:
            f.write(f'\t.include "{self.macros}"\n')
        else:
            f.write(MACROS)
        addr = BASE_ADDRESS
        if type(self.limit) is float:  # infinite end
            end = rom.size | BASE_ADDRESS
        else:
            end = min(rom.size, self.limit & 0xffffff) | BASE_ADDRESS
        mode, flags, count = BYTE, 0, 0
        while addr < end:
            next_addr = left_gt(self.labels, addr)  # Address of the next label after this one, if any
            addr_flags = self.flags[addr]  # Flags at this address
            old_mode = mode

            if addr_flags == 0 and flags != 0:  # Switch to byte mode
                mode = BYTE
            elif addr_flags & FLAG_EXEC and not (flags & FLAG_EXEC):  # Switch to code mode
                mode = THUMB
            elif addr_flags & FLAG_WORD and not (flags & FLAG_WORD) and not (addr_flags & FLAG_EXEC):
                mode = WORD
            # Various things can force a switch to BYTE mode
            if mode == THUMB:
                ins, = rom.dist(addr, 1)
                offset = 4 if ins.id == ARM_INS_BL else 2  # BL's are the only 4 byte instruction
                if next_addr and addr + offset > next_addr:  # Switch to byte mode to avoid skipping over label
                    _name = self.label_for(next_addr)
                    warn(f'{addr:08X}: THUMB instruction "{ins.mnemonic}" overlaps label at {next_addr:08X} ({_name})')
                    mode = BYTE
                    addr_flags &= ~FLAG_EXEC
            elif mode == WORD:
                offset = 4
                if next_addr and addr + offset > next_addr:
                    warn(f'{addr:08X}: Word overlaps label at {next_addr:08X} ({self.label_for(next_addr)})')
                    mode = BYTE
                    addr_flags &= ~FLAG_WORD

            # If switching out of byte mode mid-line, write a newline
            if old_mode == BYTE and mode != BYTE and count != 0:
                count = 0
                f.write('\n')

            label_type = self.label_map.get(addr, None)  # Type of label
            label = None if label_type is None else self.label_for(addr)
            comment = ''

            if label_type == FUNC:
                func = label
                if (addr & (~3)) == addr:  # Function is word aligned
                    label = f'\tthumb_func_start {func}\n{func}:'
                else:
                    label = f'\tnon_word_aligned_thumb_func_start {func}\n{func}:'
                if func[:4] != 'sub_':
                    comment += f' @ {addr:08X}'
            elif label:
                label += ':'

            if mode == THUMB:
                if ins.id in (ARM_INS_BL, ARM_INS_B):
                    target = int(ins.op_str[1:], base=16)
                    if target in self.label_map:  # BL to label
                        name = self.label_for(target)
                        emit = f'{ins.mnemonic} {name}'
                    else:  # Emit raw bytes
                        warn(f'{addr:08X}: Missing target for "{ins.mnemonic}": {target:08X}')
                        i = rom.read(addr, offset)
                        if offset == 4:
                            emit = f'.4byte 0x{i:08X} @ {ins.mnemonic} _{target:08X}'
                        else:
                            emit = f'.2byte 0x{i:04X} @ {ins.mnemonic} _{target:08X}'
                elif ins.id == ARM_INS_LDR:
                    m = load_re.match(ins.op_str)
                    op_str = ins.op_str
                    if m:
                        target = ((addr+4) & (~2)) + int(m.group(1), base=16)
                        if target in self.label_map:
                            name = self.label_for(target)
                            op_str = ins.op_str[:ins.op_str.index('[')] + name
                        else:
                            warn(f'{addr:08X}: Missing target for "ldr {op_str}": {target:08X}')
                        value = rom.read(target, 4)
                    emit = f'{ins.mnemonic} {op_str} @ =0x{value:08X}'  # QOL; comment value read
                elif ins.id in INVALID_IDS or ins.id == ARM_INS_ADR:  # TODO: Fix adr
                    emit = f'.2byte 0x{rom.read(addr, 2):04X}'
                # This is needed to convert add rx, sp, rx into add rx, sp
                elif ins.id == ARM_INS_ADD and ins.mnemonic == 'add' and '#' not in ins.op_str and ins.op_str.count(',') == 2:  # TODO: Hack
                    emit = f'add {ins.op_str[:-4]}'
                else:
                    emit = f'{ins.mnemonic} {ins.op_str}'
                if DEBUG and ins.id == ARM_INS_BX:
                    if 'r7' in ins.op_str:
                        dprint(f'DEBUG: {addr:08X} bx r7')
                    emit += f' @ {rom.read(addr, 2):04X}'

                if label:
                    f.write(f'{label}{comment}\n')
                if DEBUG:
                    f.write(f'\t{emit} @ {addr:08X}\n')
                else:
                    f.write(f'\t{emit}\n')
            elif mode == WORD:
                value = rom.read(addr, 4)
                if label:
                    emit = f'{label} .4byte 0x{value:08X}'
                else:
                    emit = f'\t.4byte 0x{value:08X}'
                if DEBUG:
                    comment += f' @ {addr_flags}'
                f.write(f'{emit}{comment}\n')
            elif mode == BYTE:
                offset = 1
                if old_mode != BYTE:
                    count = 0
                if label:
                    if count != 0:
                        f.write(f'\n')
                    f.write(f'{label}{comment}\n')
                    count = 0
                value = rom.read(addr, 1)
                if count == 0:
                    f.write(f'\t.byte 0x{value:02X}')
                    count = 1
                elif count == 15:
                    f.write(f', 0x{value:02X}\n')
                    count = 0
                else:
                    f.write(f', 0x{value:02X}')
                    count += 1
            flags = addr_flags
            addr += offset

    def disassemble(self, rom, f):
        if type(self.limit) is float:
            eprint(f'Disassembling ROM from 0x{BASE_ADDRESS:08X}:')
        else:
            eprint(f'Disassembling ROM from 0x{BASE_ADDRESS:08X}:0x{self.limit:08X}')
        self.analyze_rom(rom)
        self.dump(rom, f)


def parse_int(n):
    return int(n, 0)


# func_type? address module name?
cfg_re = re.compile(r'(thumb_func|arm_func)?\s+0x([0-9a-fA-F]{7,8})(?:\s+(\S+\.s))?(?:\s+(\S+)\r?\n)?')


def read_config(path):
    global cfg_re
    addr_map = {}
    with open(path, 'r') as f:
        for line in f:
            index = line.find('#')
            if index != -1:
                line = line[:index]
            m = cfg_re.match(line)
            if m:
                func_type, addr, module, name = m.groups()
                addr = int(addr, 16)
                name = name if name else None
                if func_type in (None, 'thumb_func'):
                    addr_map[addr] = name, module
    return addr_map


def write_config(addr_map, path):
    with open(path, 'w', buffering=1) as f:
        for addr in sorted(addr_map):
            name, module = addr_map[addr]
            parts = [f'0x{addr:07X}']
            if module:
                parts.append(module)
            if name:
                parts.append(name)
            f.write(' '.join(parts) + '\n')


parser = argparse.ArgumentParser(prog='luvdis')
parser.add_argument('rom', type=str)
parser.add_argument('-o', type=str, dest='out', default=None, metavar='output')
parser.add_argument('-c', '--config', type=str, dest='config', default=None)
parser.add_argument('-D', '--debug', action='store_true', dest='debug')
parser.add_argument('--min_calls', type=int, default=2)
parser.add_argument('--min_length', type=int, default=3)
parser.add_argument('--stop', type=parse_int, default=float('inf'))
parser.add_argument('--macros', type=str, default=None)


def main(args):
    global DEBUG
    parsed = parser.parse_args(args)
    DEBUG = parsed.debug
    if parsed.config:
        functions = {addr: name for addr, (name, _) in read_config(parsed.config).items()}
    else:
        functions = {0x0800024c: 'AgbMain', 0x08000604: 'HBlankIntr'}
    state = State(functions, parsed.min_calls, parsed.min_length, parsed.stop, parsed.macros)
    rom = ROM(parsed.rom)
    if parsed.out is None:
        f = sys.stdout
        eprint(f'No output file specified. Printing to stdout.')
        state.disassemble(rom, f)
    else:
        with open(parsed.out, 'w', buffering=1) as f:
            state.disassemble(rom, f)


if __name__ == '__main__':
    main(sys.argv[1:])
