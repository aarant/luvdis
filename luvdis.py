import sys
import re
import os.path
import argparse
import time
from math import isnan
from bisect import bisect_left, bisect_right
from io import BytesIO
from collections import defaultdict, deque

from decoder import disasm, Opcode, Reg, BRANCHES, signed
from decoder import Thumb1, Thumb2, Thumb3, Thumb4, Thumb5, Thumb6, Thumb78, Thumb910, Thumb11, Thumb12, Thumb13


DEBUG = True
__version__ = '0.1.0'


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


class UndefInt:
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
        return 'unknown?'


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
        self.unexpanded = functions.copy() if functions else {}  # Maps addr -> function name or None
        self.functions = {}  # addr -> (name, end)
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

    def analyze_rom(self, rom):  # Analyze a ROM
        pushes = set()  # Set of push {xx, lr} instruction locations
        self.flags = AddrFlags(rom.size)
        # Build instruction tables, etc for later
        for ins in rom.dist(self.start):  # TODO: Debug
            addr = ins.address
            if addr >= self.stop:
                break
            debug = False  # TODO: Debug
            # THUMB.5
            if ins.id == Opcode.bx:
                self.bxs.append(addr)
            elif ins.id in (Opcode.add, Opcode.mov) and ins.op_str[:2] == 'pc':
                self.forks.append(addr)
            # THUMB.6
            elif ins.id == Opcode.ldr and hasattr(ins, 'target'):
                self.loads.append((addr, ins.target))
            # TODO: Track THUMB.12 adr?
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
            if debug:
                input(f'{ins.address:08x} {ins}')
        # Merge forks with bxs
        self.forks.extend(self.bxs)
        for to_sort in self._to_sort:  # Sort all sorted lists
            to_sort.sort()
        # Intersect call destination and entry sets and add possible functions
        eprint(f'Found {len(self.unexpanded)} functions')
        self.guess_funcs(rom, pushes)
        eprint(f'Found {len(self.unexpanded)} functions')
        # Repeatedly expand known functions until there are no changes
        changed = True
        while changed:
            changed = self.analyze_funcs(rom)
            eprint(f'Found {len(self.functions)} functions')
        self.make_labels(rom)

    def guess_funcs(self, rom, entries):  # Guess functions based on heuristic
        for maybe_func in entries:
            if maybe_func not in self.unexpanded and maybe_func < self.stop:
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
                        exit_behavior = target == BASE_ADDRESS and state[13] == initial_stack
                        break
                    elif ins.id == Opcode.pop:  # pop {pc}
                        exit_behavior = (state[15] & 0xffffff) == BASE_ADDRESS
                        break
                    else:  # ADD/MOV pc
                        target = state[ins.rd] & 0xffffffff
                        end = addr = ins.address+2
                        exit_behavior = target == BASE_ADDRESS and state[13] == initial_stack
                        break
                expanded[start] = exit_behavior
                ranges.append((start, end))
            starts = new_starts
        # Tally exit behaviors
        l = [1 if behavior else 0 for behavior in expanded.values() if behavior is not None]
        total, exited = len(l), sum(l)
        return exited, total, labels, calls, ranges

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
                    target = ins.target
                    if target < self.stop:
                        self.label_map[target] = BRANCH  # Mark as branch
                        if target not in expanded:  # Add target as a potential start run
                            if target > 0x081B32B0:
                                dprint(f'DEBUG: Target {target:08X} reached at {b:08X}: {ins.mnemonic} {ins.op_str}')
                            new_starts.add(target)
                    else:  # Forbidden jump, not a function!
                        return None, set()
                    if ins.mnemonic == 'b':  # Unconditional branch; stop execution
                        end = min(end, b+2)
                        break
                for bl in find_bounds(self.branch_links, start, end):  # Look at each BL
                    ins, = rom.dist(bl, 1)
                    target = ins.target
                    if target < self.stop:
                        # dprint(f'OOF bl @ {bl:08X} -> {target:08X}')
                        self.label_map[target] = BRANCH
                        calls.add(target)
                    else:
                        return None, set()
                # Mark the whole region from start:end as executable
                self.flags[start:end] |= FLAG_EXEC
                # Mark each load target as readable  TODO
                ninf = -float('inf')
                for ld, target in find_bounds(self.loads, (start, ninf), (end, ninf)):
                    if target < self.stop:
                        self.label_map[target] = WORD
                        self.flags[target:target+4] |= FLAG_WORD
                # Take the max of the exit address and the end of this run
                exit_addr = max(exit_addr, end)
                expanded.add(start)
            starts = new_starts
        return exit_addr, calls

    def analyze_funcs(self, rom):
        changed = False
        print(f'\rFound {len(self.functions)} functions', end='')
        for func, name in self.unexpanded.copy().items():
            exited, total, labels, calls, ranges = self.analyze_func(rom, func)
            # print(f'func {func:08X} {exited}/{total}')
            if total and exited == total:  # DEBUG
                pass
            elif func == 0x08000348:
                input()
                continue
            else:
                continue
            self.label_map.update(labels)
            for start, end in ranges:
                self.flags[start:end] |= FLAG_EXEC
            for target in calls:
                if target not in self.functions and target not in self.unexpanded:
                    self.unexpanded[target] = None
                    changed = True
            self.functions[func] = (name, None)  # TODO: End?
            self.unexpanded.pop(func)
            print(f'\rFound {len(self.functions)} functions', end='')
        print()
        input('foo')
        return changed

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
            if end is not None:
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
        if True:  # DEBUG cfg output
            addr_map = {addr: (name, None) for addr, (name, _) in self.functions.items()}
            write_config(addr_map, 'luvdis.cfg')
        f.write(ASM_PRELUDE)
        if self.macros:
            f.write(f'\t.include "{self.macros}"\n')
        else:
            f.write(MACROS)
        addr = BASE_ADDRESS
        if type(self.stop) is float:  # infinite end
            end = rom.size | BASE_ADDRESS
        else:
            end = min(rom.size, self.stop & 0xffffff) | BASE_ADDRESS
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
                    # bx with nonzero rd, see THUMB.5
                    emit = f'.inst 0x{value:04X}' if value & 3 != 0 else str(ins)
                elif ins.id == Opcode.ldr and hasattr(ins, 'target'):  # Convert PC-relative loads into labels
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

    def disassemble(self, rom, f):
        if type(self.stop) is float:
            eprint(f'Disassembling ROM from 0x{self.start:08X}:')
        else:
            eprint(f'Disassembling ROM from 0x{self.start:08X}:0x{self.stop:08X}')
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
parser.add_argument('--start', type=parse_int, default=BASE_ADDRESS)
parser.add_argument('--stop', type=parse_int, default=float('inf'))
parser.add_argument('--macros', type=str, default=None)


def main(args):
    global DEBUG
    parsed = parser.parse_args(args)
    DEBUG = parsed.debug
    if parsed.config:
        functions = {addr: name for addr, (name, _) in read_config(parsed.config).items()}
    else:
        functions = {0x0800024c: 'AgbMain', 0x08000604: 'HBlankIntr', 0x08000348: 'UpdateLinkAndCallCallbacks'}
        functions = {0x08000348: 'UpdateLinkAndCallCallbacks'}
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
    main(sys.argv[1:])
