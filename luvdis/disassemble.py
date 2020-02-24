""" ROM disassembly/dumping tools. """
import sys

import os.path
import pkg_resources
from math import inf as INF
from bisect import bisect_left, bisect_right
from io import BytesIO
from collections import defaultdict

from luvdis import __version__
from luvdis.config import write_config
from luvdis.decoder import disasm, Opcode, Reg, BRANCHES
from luvdis.decoder import Thumb1, Thumb2, Thumb3, Thumb4, Thumb5, Thumb6, Thumb78, Thumb910, Thumb11, Thumb12, Thumb13


DEBUG = False
# ROM flags
FLAG_EXEC = 1
FLAG_WORD = 2
# Label types
FUNC = 0
BRANCH = 1
BYTE = 2  # Also a dumping mode
WORD = 3  # Also a dumping mode
# Dumping modes
THUMB = 0

BASE_ADDRESS = 0x08000000
ASM_PRELUDE = f'@ Generated with Luvdis v{__version__}\n.syntax unified\n.text\n'
MACROS = pkg_resources.resource_string('luvdis', 'functions.inc').decode('utf-8')


def _set_debug(debug):
    global DEBUG
    DEBUG = debug


class ROM:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.buffer = f.read()
            self.size = len(self.buffer)
            self.f = BytesIO(self.buffer)
        dprint(f'Loaded {os.path.basename(path)}')

    def read(self, addr, size=1, safe=True):
        if safe:
            cursor = self.f.tell()
        self.f.seek(addr & 0xffffff)
        b = self.f.read(size)
        if safe:
            self.f.seek(cursor)
        return int.from_bytes(b, 'little', signed=False)

    def dist(self, addr=0x08000000, count=None):
        self.f.seek(addr & 0xffffff)
        if count is None:
            yield from disasm(self.f, addr)
        else:
            yield from disasm(self.f, addr, count)


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


class RomFlags:  # Markable address flags
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
            n = ins.size
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
            n = ins.size
            return self[base:base+n]


class UndefInt:  # In integer-like object that is only equal to itself and is closed under all operations
    def __init__(self):
        pass

    def __eq__(self, other):
        return self is other

    def __ne__(self, other):
        return self is not other

    def __lt__(self, other):
        return False

    __gt__ = __le__ = __lt__

    def __pos__(self):
        return self

    __neg__ = __abs__ = __invert__ = __floor__ = __ceil__ = __trunc__ = __pos__

    def __add__(self, other):
        return self

    __sub__ = __mul__ = __floordiv__ = __div__ = __truediv__ = __mod__ = __divmod__ = __pow__ = __add__

    __lshift__ = __rshift__ = __and__ = __or__ = __xor__ = __add__

    __radd__ = __rsub__ = __rmul__ = __rfloordiv__ = __rdiv__ = __rtruediv__ = __rmod__ = __rdivmod__ = __rpow__ = __add__

    __rlshift__ = __rrshift__ = __rand__ = __ror__ = __rxor__ = __add__

    def __str__(self):
        return 'undefined'

    def __format__(self, _):
        return '?'


class CPUState:
    unknown = UndefInt()
    return_addr = BASE_ADDRESS
    __slots__ = ('reg', 'stack', 'sp')

    def __init__(self):
        self.reg = [self.unknown for _ in range(16)]
        self.reg[14] = self.return_addr
        self.reg[13] = 0x030007F0
        self.stack = [self.unknown for _ in range(16)]
        self.sp = 0

    def emulate(self, rom, addr):
        ins = None
        for ins in rom.dist(addr):
            # print(f'{self}\n{ins} @ {ins.address:08X}')
            self[15] = ins.address + 4
            if isinstance(ins, Thumb1):
                if ins.id in (Opcode.lsr, Opcode.asr) and ins.offset == 0:
                    offset = 32
                else:
                    offset = ins.offset
                self.throp(ins.rd, ins.rs, offset, ins.id)
            elif isinstance(ins, Thumb2):
                self.throp(ins.rd, ins.rs, ins.n, ins.id)
            elif isinstance(ins, Thumb3) and ins.id != Opcode.cmp:
                self.throp(ins.rd, ins.rd, ins.imm, ins.id)
            elif isinstance(ins, Thumb4):
                self.throp(ins.rd, ins.rd, ins.rs, ins.id)
            elif isinstance(ins, Thumb5):
                if ins.id == Opcode.bx:
                    break
                self.throp(ins.rd, ins.rd, ins.rs, ins.id)
                if ins.id != Opcode.cmp and ins.rd == 15:  # destination pc
                    break
            elif isinstance(ins, Thumb6):
                value = rom.read(ins.target, 4)
                self[ins.rd] = value
                break
            elif isinstance(ins, Thumb78):
                self.load(rom, ins.rd, ins.rb, ins.ro, ins.id)
            elif isinstance(ins, Thumb910):  # TODO: Multiply offsets
                self.load(rom, ins.rd, ins.rb, ins.imm, ins.id)
            elif isinstance(ins, Thumb11):  # Load/store SP relative
                index = self.sp - ins.imm
                if ins.id == Opcode.ldr:
                    if 0 <= index < len(self.stack):
                        self[ins.rd] = self.stack[index]
                    else:
                        self[ins.rd] = self.unknown
                else:
                    if 0 <= index < len(self.stack):
                        self.stack[index] = self[ins.rd]
            elif isinstance(ins, Thumb12):
                self.throp(ins.rd, ins.rs, ins.imm*4, ins.id)
            elif isinstance(ins, Thumb13):
                offset = ins.imm if ins.id == Opcode.add else -ins.imm
                self.sp -= offset
                for _ in range(len(self.stack)-self.sp):
                    self.stack.append(self.unknown)
                self[13] += offset*4
            elif ins.id == Opcode.push:
                rlist = ins.rlist
                for i in reversed(range(16)):
                    if rlist & (1 << i):  # Decrement and push
                        self[13] -= 4
                        value = self[i]
                        if self.sp >= len(self.stack):
                            self.stack.append(value)
                        else:
                            self.stack[self.sp] = value
                        self.sp += 1
            elif ins.id == Opcode.pop:
                rlist = ins.rlist
                for i in range(16):
                    if rlist & (1 << i):  # Increment after and push
                        self.sp -= 1
                        if not (0 <= self.sp < len(self.stack)):
                            value = self.unknown
                        else:
                            value = self.stack[self.sp]
                        self[i] = value
                        self[13] += 4
                if ins.touched(15):  # pop {pc}
                    break
            elif ins.id in (Opcode.stm, Opcode.ldm):
                bits = 0
                for i in range(8):
                    if ins.rlist & (1 << i):
                        bits += 1
                self[ins.rb] += 4*bits
            elif ins.id in BRANCHES:
                break
            elif ins.id == Opcode.bl:
                self[0] = self.unknown
                self[14] = ins.address+4
                break
            elif ins.id == Opcode.ill:
                break
        return ins

    def throp(self, rd, rs, imm, op):
        value = self[rs]
        if type(imm) is Reg:
            imm = self.reg[imm]
        if op == Opcode.lsl:
            value = (value << imm)
        elif op in (Opcode.lsr, Opcode.asr):
            value = (value >> imm)
        elif op == Opcode.add:
            value += imm
        elif op == Opcode.sub:
            value -= imm
        elif op == Opcode.mov:
            value = imm
        elif op == Opcode.AND:
            value &= imm
        elif op == Opcode.eor:
            value ^= imm
        elif op == Opcode.adc:  # TODO: Add with carry
            value += imm
        elif op == Opcode.sbc:  # TODO: Subtract with carry
            value -= imm
        elif op == Opcode.ror:
            imm %= 32
            value = (value >> imm) | (value << (32-imm))
        elif op in (Opcode.tst, Opcode.cmp, Opcode.cmn):
            return
        elif op == Opcode.neg:
            value = -imm
        elif op == Opcode.orr:
            value |= imm
        elif op == Opcode.mul:
            value *= imm
        elif op == Opcode.bic:
            value = value & (~imm)
        elif op == Opcode.mvn:
            value = ~imm
        self[rd] = value

    def load(self, rom, rd, rb, offset, op):
        addr = self[rb]
        cursor = rom.f.tell()
        if type(offset) is Reg:
            offset = self[offset]
        addr += offset
        if addr == self.unknown or (addr & 0xff000000) != BASE_ADDRESS:
            return self.unknown
        if op == Opcode.ldr:
            value = rom.read(addr, 4)
        elif op == Opcode.ldrb:
            value = rom.read(addr, 1)
        elif op == Opcode.ldrh:
            value = rom.read(addr, 2)
        elif op in (Opcode.ldsb, Opcode.ldsh):
            value = self.unknown
        else:
            return
        assert rom.f.tell() == cursor
        self[rd] = value

    def copy(self):
        new_state = CPUState()
        new_state.reg = self.reg[:]
        new_state.stack = self.stack[:]
        new_state.sp = self.sp
        return new_state

    def __getitem__(self, i):
        return self.reg[i] % 2**32

    def __setitem__(self, i, value):
        self.reg[i] = value % 2**32

    def __str__(self):
        lines = []
        for row in range(4):
            parts = []
            for col in range(4):
                i = col + 4*row
                value = self[i] & 0xffffffff
                if value != self.unknown:
                    value = f'{value:08X}'
                else:
                    value = 'unknown '
                parts.append(f'r{i:02d}: {value}')
            lines.append(' '.join(parts))
        parts = []
        for i, value in enumerate(self.stack):
            if i == self.sp:
                parts.append(f'>{value:08X}')
            else:
                parts.append(f' {value:08X}')
        lines.append('[' + ','.join(parts) + ']')
        return '\n'.join(lines)


class State:
    def __init__(self, functions=None, min_calls=2, min_length=3, start=BASE_ADDRESS, stop=INF, macros=None):
        self.unexpanded = {}
        self.module_addrs = {}
        if functions:
            for addr, value in functions.items():
                if type(value) is tuple:
                    name, module = value
                    if module:
                        self.module_addrs[addr] = module
                else:
                    name = value
                self.unexpanded[addr] = name
        self.functions = {}  # addr -> (name, end)
        self.not_funcs = set()
        self.min_calls, self.min_length, self.start, self.stop = min_calls, min_length, start, stop
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

    def analyze_rom(self, rom, guess=True):  # Analyze a ROM
        if type(self.stop) is float:
            eprint(f'Disassembling ROM from 0x{self.start:08X}:')
        else:
            eprint(f'Disassembling ROM from 0x{self.start:08X}:0x{self.stop:08X}')
        pushes = set()  # Set of push {xx, lr} instruction locations
        self.flags = RomFlags(rom.size)
        # Build instruction tables, etc for later
        for ins in rom.dist(self.start):
            addr = ins.address
            if addr >= self.stop:
                break
            # THUMB.5
            if ins.id == Opcode.bx:
                self.bxs.append(addr)
            elif ins.id in (Opcode.add, Opcode.mov) and ins.op_str[:2] == 'pc':
                self.forks.append(addr)
            # THUMB.6
            elif ins.id == Opcode.ldr and hasattr(ins, 'target'):
                self.loads.append((addr, ins.target))
            # TODO: Track THUMB.12 adr as a load target?
            # THUMB.14
            elif ins.id == Opcode.push and ins.touched(Reg.lr):
                # Add addr and preceding locations as possible function entries
                pushes.add(max(BASE_ADDRESS, addr-4))
                pushes.add(max(BASE_ADDRESS, addr-2))
                pushes.add(addr)
            elif ins.id == Opcode.pop and ins.touched(Reg.pc):  # `pop {pc}`, though rare, is nonlinear
                self.forks.append(addr)
            # THUMB.16, THUMB.18
            elif ins.id in BRANCHES:
                self.branch_to[ins.target].add(addr)
                self.branches.append(addr)
            # THUMB.19
            elif ins.id == Opcode.bl:
                self.call_to[ins.target].add(addr)
                self.branch_links.append(addr)
                # dprint(f'bl @ {addr:08X} -> {ins.target:08X}')
            # Illegal instructions
            elif ins.id == Opcode.ill:
                self.data.append(addr)
            if False:
                input(f'{ins.address:08x} {ins}')
        # Merge forks with bxs
        self.forks.extend(self.bxs)
        for to_sort in self._to_sort:  # Sort all sorted lists
            to_sort.sort()
        # Expand all provided functions
        eprint(f'{len(self.unexpanded)} functions provided')
        changed = self.analyze_funcs(rom, 0)
        if not guess:  # Exit here if not guessing
            self.make_labels(rom)
            return
        while changed:
            changed = self.analyze_funcs(rom, 2/3)  # TODO: Add configurable threshold
        eprint(f'Found {len(self.functions)} functions')
        # Guess functions based on push-bl intersection
        self.guess_funcs(rom, pushes)
        changed = True
        while changed:
            changed = self.analyze_funcs(rom, 1)
        eprint(f'Found {len(self.functions)} functions')
        # TODO: library detection
        # TODO: Reverse call searching
        dprint(f'{len(self.not_funcs)} not-funcs')
        self.make_labels(rom)

    def guess_funcs(self, rom, entries):  # Guess functions based on heuristic
        dicts = (self.functions, self.unexpanded, self.not_funcs)
        for maybe_func in entries:
            if maybe_func < self.stop and all(maybe_func not in d for d in dicts):
                ncalls = len(self.call_to[maybe_func])  # Number of calls pointing here
                if ncalls < self.min_calls:  # Not enough calls; reject
                    continue
                # Only accept functions with at least min_length legal instructions
                if any(ins.id == Opcode.ill for ins in rom.dist(maybe_func, self.min_length)):
                    continue
                if maybe_func > 0x081B32B0:
                    dprint(f'DEBUG: Func {maybe_func:08X} added')
                self.unexpanded[maybe_func] = None  # Accept the function

    def analyze_func(self, rom, addr, state=None):
        state = state if state else CPUState()
        initial_stack = state[13]  # Initial value of stack pointer
        starts = {addr: state}
        expanded = {}  # Start addresses -> exit behavior seen so far
        labels = {}  # Addresses -> label type
        calls = {}  # Addresses -> call state
        ranges = []  # List of (start:end) tuples of executable regions
        while starts:  # Continue as long as there are paths to explore
            new_starts = {}
            for start, state in sorted(starts.items()):  # Emulate from each start address
                addr = start
                while True:  # Follow codepath until fork
                    ins = state.emulate(rom, addr)  # Emulate until first relevant instruction
                    # Hitting an illegal instruction, or the end of the ROM, is misbehavior
                    if ins is None or ins.id == Opcode.ill:
                        exit_behavior = False
                        end = rom.size | 0x08000000 if ins is None else ins.address
                        break
                    elif ins.id == Opcode.ldr:  # Mark target as WORD
                        end = addr = ins.address+2
                        target = ins.target
                        if target < self.stop:  # TODO: Is this necessary?
                            labels[target] = WORD
                            ranges.append((target, target+4, FLAG_WORD))
                    elif ins.id in BRANCHES:
                        target = ins.target
                        end = addr = ins.address+2
                        if target < self.stop:
                            labels[target] = BRANCH
                            if target not in expanded:  # Add target as start
                                new_starts[target] = state.copy()
                            exit_behavior = None
                            if ins.id == Opcode.b:  # Fork on unconditional branch
                                break
                        else:
                            exit_behavior = False  # Branching OOB is misbehavior
                            break
                    elif ins.id == Opcode.bl:
                        target = ins.target
                        end = addr = ins.address+4
                        if target < self.stop:
                            labels[target] = BRANCH
                            calls[target] = state.copy()  # Copy state to start of function
                            exit_behavior = None
                        else:
                            exit_behavior = False  # Calling an OOB function is misbehavior
                            break
                    elif ins.id == Opcode.bx:
                        target = state[ins.rs] & 0xffffffff
                        end = addr = ins.address+2
                        # Well-behaved iff returned properly and the stack is safe
                        exit_behavior = target == state.return_addr and state[13] == initial_stack
                        break
                    elif ins.id == Opcode.pop:  # pop {pc}
                        end = ins.address+2
                        exit_behavior = (state[15] & 0xffffff) == state.return_addr
                        break
                    else:  # ADD/MOV pc
                        target = state[ins.rd] & 0xffffffff
                        end = addr = ins.address+2
                        exit_behavior = target == state.return_addr and state[13] == initial_stack
                        break
                expanded[start] = exit_behavior
                ranges.append((start, end, FLAG_EXEC))
            starts = new_starts
        # Tally exit behaviors
        exits = [1 if behavior else 0 for behavior in expanded.values() if behavior is not None]
        total, exited = len(exits), sum(exits)
        return exited, total, labels, calls, ranges

    def analyze_funcs(self, rom, threshold=0.5):
        changed = False
        new_unexpanded = {}
        # print(f'\rFound {len(self.functions)} functions', end='')
        for func, name in self.unexpanded.items():
            exited, total, labels, calls, ranges = self.analyze_func(rom, func)
            if (total and exited/total < threshold) or (total == 0 != threshold):
                self.not_funcs.add(func)
                continue
            self.label_map.update(labels)
            for start, end, flag in ranges:
                self.flags[start:end] |= flag
            for target in calls:
                if all(target not in d for d in (self.functions, self.unexpanded, self.not_funcs, new_unexpanded)):
                    new_unexpanded[target] = None
                    changed = True
            self.functions[func] = (name, None)  # TODO: Track the ends of functions?
            # print(f'\rFound {len(self.functions)} functions', end='')
        # print()
        self.unexpanded = new_unexpanded
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

    def dump(self, rom, path=None, config_output=None):
        if config_output:  # Optionally, write updated function list
            addr_map = {addr: (name, self.module_addrs.get(addr, None)) for addr, (name, _) in self.functions.items()}
            write_config(addr_map, config_output)
        # Setup initial module & file
        folder, module = os.path.split(path) if path else (None, None)
        f = None if path else sys.stdout
        # Setup start and end addresses
        addr = self.start
        if type(self.stop) is float:  # End is the final address in the ROM
            end = rom.size | BASE_ADDRESS
        else:
            end = min(rom.size, self.stop & 0xffffff) | BASE_ADDRESS
        if addr not in self.module_addrs and module:
            self.module_addrs[addr] = module
        mode, flags, count = BYTE, 0, 0
        # Main disassembly loop
        while addr < end:
            next_addr = left_gt(self.labels, addr)  # Address of the next label after this one, if any
            addr_flags = self.flags[addr]  # Flags at this address
            old_mode = mode

            # Determine which mode to switch into
            if addr_flags == 0 and flags != 0:  # Switch to byte mode
                mode = BYTE
            elif addr_flags & FLAG_EXEC and not (flags & FLAG_EXEC):  # Switch to code mode
                mode = THUMB
            elif addr_flags & FLAG_WORD and not (flags & FLAG_WORD) and not (addr_flags & FLAG_EXEC):
                mode = WORD
            # Various things can force a switch to BYTE mode
            if mode == THUMB:
                ins, = rom.dist(addr, 1)
                offset = 4 if ins.id == Opcode.bl else 2  # BL's are the only 4 byte instruction
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

            # Determine label and comment
            # TODO: Check which labels are used in other modules--they must be marked as global for the assembler!
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

            # Switch module output
            if f is not sys.stdout and addr in self.module_addrs:
                new_module = self.module_addrs[addr]
                if new_module != module or f is None:
                    module = new_module
                    path = os.path.join(folder, module)
                    eprint(f"{addr:08X}: module '{path}'")
                    if f:
                        if count != 0:
                            f.write('\n')
                        f.close()
                    f = open(path, 'w', buffering=1)
                    f.write(ASM_PRELUDE)
                    if self.macros:
                        f.write(f'.include "{self.macros}"\n')
                    else:
                        f.write(MACROS)
                    count = 0  # Reset byte count

            # If switching out of byte mode mid-line, write a newline
            if old_mode == BYTE and mode != BYTE and count != 0:
                count = 0
                f.write('\n')

            # Emit code or data
            if mode == THUMB:
                if ins.id == Opcode.bl or ins.id in BRANCHES:
                    target = ins.target
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
                elif ins.id == Opcode.bx:
                    value = rom.read(addr, 2)
                    # Assembler cannot emit bx with nonzero rd, see THUMB.5 TODO: Should these be illegal?
                    emit = f'.inst 0x{value:04X}' if value & 3 != 0 else str(ins)
                elif ins.id == Opcode.ldr and isinstance(ins, Thumb6):  # Convert PC-relative loads into labels
                    target = ins.target
                    if target in self.label_map:
                        name = self.label_for(target)
                        op_str = ins.op_str[:ins.op_str.index('[')] + name
                    else:
                        op_str = ins.op_str
                        warn(f'{addr:08X}: Missing target for "ldr {op_str}": {target:08X}')
                    value = rom.read(target, 4)
                    emit = f'{ins.mnemonic} {op_str} @ =0x{value:08X}'  # QOL; comment value read
                else:
                    emit = str(ins)
                if DEBUG and ins.id == Opcode.bx:
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
                if value & 1 and self.label_map.get(value-1, None) == FUNC:
                    value = self.label_for(value-1)  # Reference THUMB function name
                else:
                    value = f'0x{value:08X}'
                if label:
                    emit = f'{label} .4byte {value}'
                else:
                    emit = f'\t.4byte {value}'
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
        # Close the file if necessary
        if f is not sys.stdout and f:
            if count != 0:
                f.write('\n')
            f.close()
