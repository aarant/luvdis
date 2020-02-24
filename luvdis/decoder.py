""" ARM7TDMI THUMB instruction decoder. """
import io
import time

from io import BytesIO
from enum import IntEnum, auto


class Reg(IntEnum):
    r0 = 0
    r1 = 1
    r2 = 2
    r3 = 3
    r4 = 4
    r5 = 5
    r6 = 6
    r7 = 7
    r8 = 8
    r9 = 9
    r10 = 10
    r11 = 11
    r12 = 12
    sp = 13
    r13 = 13
    lr = 14
    r14 = 14
    pc = 15
    r15 = 15


class Opcode(IntEnum):
    ill = auto()
    # THUMB.1
    lsl = auto()
    lsr = auto()
    asr = auto()
    # THUMB.2
    add = auto()
    sub = auto()
    # THUMB.3
    mov = auto()
    cmp = auto()
    # THUMB.4
    AND = auto()
    eor = auto()
    adc = auto()
    sbc = auto()
    ror = auto()
    tst = auto()
    neg = auto()
    cmn = auto()
    orr = auto()
    mul = auto()
    bic = auto()
    mvn = auto()
    # THUMB.5
    bx = auto()
    # THUMB.6
    ldr = auto()
    # THUMB.7
    STR = auto()
    strb = auto()
    ldrb = auto()
    # THUMB.8
    strh = auto()
    ldsb = auto()
    ldrh = auto()
    ldsh = auto()
    # THUMB.12
    adr = auto()
    # THUMB.14
    push = auto()
    pop = auto()
    # THUMB.15
    stm = auto()
    ldm = auto()
    # THUMB.16
    beq = auto()
    bne = auto()
    bcs = auto()
    bcc = auto()
    bmi = auto()
    bpl = auto()
    bvs = auto()
    bvc = auto()
    bhi = auto()
    bls = auto()
    bge = auto()
    blt = auto()
    bgt = auto()
    ble = auto()
    # THUMB.17
    swi = auto()
    # THUMB.18
    b = auto()
    # THUMB.19
    bl = auto()


# Set of all unconditional/conditional branch opcodes
BRANCHES = {Opcode.beq, Opcode.bne, Opcode.bcs, Opcode.bcc, Opcode.bmi, Opcode.bpl, Opcode.bvs, Opcode.bvc,
            Opcode.bhi, Opcode.bls, Opcode.bge, Opcode.blt, Opcode.bgt, Opcode.ble, Opcode.b}


# See GBATEK: https://problemkaputt.de/gbatek.htm#thumbinstructionsummary


class ThumbInstr:  # ABC
    size = 2
    @property
    def mnemonic(self):
        return self.id.name.lower()

    @property
    def target(self):
        return None

    def __str__(self):
        return f'{self.mnemonic} {self.op_str}'


class ThumbIll(ThumbInstr):

    def __init__(self, id, address, value):
        self.id, self.address, self.value = Opcode.ill, address, value

    @property
    def op_str(self):
        return ''

    def __str__(self):
        return f'.2byte 0x{self.value:04X}'


class Thumb1(ThumbInstr):  # Move shifted register
    __slots__ = ('address', 'id', 'rd', 'rs', 'offset')

    def __init__(self, id, addr, rd, rs, offset):
        self.id, self.address, self.rd, self.rs, self.offset = id, addr, rd, rs, offset

    @property
    def mnemonic(self):
        return self.id.name + 's'

    @property
    def op_str(self):
        if self.offset == 0 and self.id in (Opcode.lsr, Opcode.asr):  # Zero->32?
            return f'{self.rd.name}, {self.rs.name}, #0x20'
        else:
            return f'{self.rd.name}, {self.rs.name}, #0x{self.offset:02X}'


class Thumb2(ThumbInstr):  # Add/subtract
    __slots__ = ('id', 'address', 'rd', 'rs', 'n')

    def __init__(self, id, addr, rd, rs, n):
        self.id, self.address, self.rd, self.rs, self.n = id, addr, rd, rs, n

    @property
    def mnemonic(self):
        return self.id.name + 's'

    @property
    def op_str(self):
        if type(self.n) is int:
            return f'{self.rd.name}, {self.rs.name}, #0x{self.n:X}'
        else:
            return f'{self.rd.name}, {self.rs.name}, {self.n.name}'

    def __str__(self):
        if self.rd == self.rs and type(self.n) is int:  # Prevent assembler hack
            value = 0x1800 | (0x600 if self.id == Opcode.sub else 0x400) | (self.n << 6) | (self.rs << 3) | self.rd
            return f'.inst 0x{value:04X}'
        else:
            return f'{self.mnemonic} {self.op_str}'


class Thumb3(ThumbInstr):  # Move/compare/add/subtract immediate
    __slots__ = ('id', 'address', 'rd', 'imm')

    def __init__(self, id, addr, rd, imm):
        self.id, self.address, self.rd, self.imm = id, addr, rd, imm

    @property
    def mnemonic(self):
        return self.id.name + 's' if self.id != Opcode.cmp else self.id.name  # 's' on cmp is deprecated

    @property
    def op_str(self):
        return f'{self.rd.name}, #0x{self.imm:02X}'


class Thumb4(ThumbInstr):  # ALU operations
    __slots__ = ('id', 'address', 'rd', 'rs')

    def __init__(self, id, addr, rd, rs):
        self.id, self.address, self.rd, self.rs = id, addr, rd, rs

    @property
    def mnemonic(self):
        return self.id.name if self.id in (Opcode.tst, Opcode.cmp, Opcode.cmn) else self.id.name.lower() + 's'

    @property
    def op_str(self):
        return f'{self.rd.name}, {self.rs.name}'


class Thumb5(ThumbInstr):  # High register/branch exchange
    __slots__ = ('id', 'address', 'rd', 'rs')

    def __init__(self, id, addr, rd, rs):
        self.id, self.address, self.rd, self.rs = id, addr, rd, rs

    @property
    def mnemonic(self):
        if self.id == Opcode.mov and self.rd == self.rs == Reg.r8:
            return 'nop'
        return self.id.name

    @property
    def op_str(self):
        if self.id == Opcode.mov and self.rd == self.rs == Reg.r8:
            return ''
        elif self.id in (Opcode.mov, Opcode.cmp, Opcode.add):
            return f'{self.rd.name}, {self.rs.name}'
        return f'{self.rs.name}'

    @property
    def target(self):
        return self.rs if self.id == Opcode.bx else None

    def __str__(self):
        if self.id == Opcode.mov and self.rd == self.rs == Reg.r8:
            return 'nop'
        return f'{self.mnemonic} {self.op_str}'


class Thumb6(ThumbInstr):  # Load PC-relative
    __slots__ = ('id', 'address', 'rd', 'imm')

    def __init__(self, id, addr, rd, imm):
        self.id, self.address, self.rd, self.imm = Opcode.ldr, addr, rd, imm

    @property
    def op_str(self):
        return f'{self.rd.name}, [pc, #0x{self.imm*4:03X}]'

    @property
    def target(self):
        return ((self.address + 4) & (~2)) + self.imm*4


class Thumb78(ThumbInstr):  # Load/store with register offset
    __slots__ = ('id', 'address', 'rd', 'rb', 'ro')

    def __init__(self, id, address, rd, rb, ro):
        self.id, self.address, self.rd, self.rb, self.ro = id, address, rd, rb, ro

    @property
    def op_str(self):
        return f'{self.rd.name}, [{self.rb.name}, {self.ro.name}]'


class Thumb910(ThumbInstr):  # Load/store with immediate offset
    __slots__ = ('id', 'address', 'rd', 'rb', 'imm')

    def __init__(self, id, address, rd, rb, imm):
        self.id, self.address, self.rd, self.rb, self.imm = id, address, rd, rb, imm

    @property
    def op_str(self):
        if self.id in (Opcode.strb, Opcode.ldrb):
            return f'{self.rd.name}, [{self.rb.name}, #0x{self.imm:02X}]'
        elif self.id in (Opcode.strh, Opcode.ldrh):
            return f'{self.rd.name}, [{self.rb.name}, #0x{self.imm*2:02X}]'
        return f'{self.rd.name}, [{self.rb.name}, #0x{self.imm*4:02X}]'


class Thumb11(ThumbInstr):  # Load/store SP-relative
    __slots__ = ('id', 'address', 'rd', 'imm')

    def __init__(self, id, addr, rd, imm):
        self.id, self.address, self.rd, self.imm = id, addr, rd, imm

    @property
    def op_str(self):
        return f'{self.rd.name}, [sp, #0x{self.imm*4:03X}]'


class Thumb12(ThumbInstr):  # Get relative address
    __slots__ = ('id', 'address', 'rd', 'rs', 'imm')

    def __init__(self, id, address, rd, rs, imm):
        self.id, self.address, self.rd, self.rs, self.imm = Opcode.add, address, rd, rs, imm

    @property
    def op_str(self):
        return f'{self.rd.name}, {self.rs.name}, #0x{self.imm*4:03X}'

    @property
    def target(self):
        if self.rs != Reg.pc:
            return None
        return ((self.address + 4) & (~2)) + self.imm*4


class Thumb13(ThumbInstr):  # Add offset to stack pointer
    __slots__ = ('id', 'address', 'imm')

    def __init__(self, id, address, imm):
        self.id, self.address, self.imm = id, address, imm

    @property
    def mnemonic(self):
        return Opcode.add.name

    @property
    def op_str(self):
        if self.id == Opcode.sub:
            return f'sp, #-0x{self.imm*4:03X}'
        return f'sp, #0x{self.imm*4:03X}'


class Thumb14(ThumbInstr):  # Push/pop registers
    __slots__ = ('id', 'address', 'rlist')

    def __init__(self, id, address, rlist):
        self.id, self.address, self.rlist = id, address, rlist

    def touched(self, r):
        return self.rlist & (1 << r) != 0

    @property
    def op_str(self):
        regs = []
        for bit in range(16):
            if self.rlist & (1 << bit):
                regs.append(Reg(bit).name)
        return '{' + ', '.join(regs) + '}'

    def __contains__(self, r):
        return self.rlist & (1 << r) != 0


class Thumb15(ThumbInstr):  # Multiple load/store  TODO: See THUMB.15 "Strange effects"
    __slots__ = ('id', 'address', 'rb', 'rlist')

    def __init__(self, id, address, rb, rlist):
        self.id, self.address, self.rb, self.rlist = id, address, rb, rlist

    def touched(self, r):
        return self.rlist & (1 << r) != 0

    @property
    def op_str(self):
        regs = []
        for bit in range(8):
            if self.rlist & (1 << bit):
                regs.append(Reg(bit).name)
        return f'{self.rb.name}!, {{{", ".join(regs)}}}'

    def __str__(self):
        # Invalid in ARMv4: rlist or base in writeback  TODO: Handle invalid rlists elsewhere?
        if self.rlist == 0 or (self.id == Opcode.ldm and self.touched(self.rb)):
            value = 0xC000 | (0x800 if self.id == Opcode.ldm else 0) | (self.rb << 8) | self.rlist
            return f'.inst 0x{value:04X}'
        else:
            return f'{self.mnemonic} {self.op_str}'


class Thumb1618(ThumbInstr):  # Branches
    __slots__ = ('id', 'address', 'offset')

    def __init__(self, id, address, offset):
        self.id, self.address, self.offset = id, address, offset

    @property
    def target(self):
        if self.id == Opcode.b:
            return self.address + 4 + signed(self.offset, 11)*2
        return self.address + 4 + signed(self.offset, 8)*2

    @property
    def op_str(self):
        return f'#0x{self.target:X}'


class Thumb17(ThumbInstr):  # SWI
    __slots__ = ('id', 'address', 'n')

    def __init__(self, id, address, n):
        self.id, self.address, self.n = Opcode.swi, address, n

    @property
    def op_str(self):
        return f'#{self.n:d}'


class Thumb19(ThumbInstr):  # Long branch with link
    size = 4
    __slots__ = ('id', 'address', 'target')

    def __init__(self, id, address, target):
        self.id, self.address, self.target = id, address, target

    @property
    def op_str(self):
        return f'#0x{self.target:X}'


def disasm(f_or_buffer, address: int, count=float('inf')):
    """ Disassemble instructions from a file-like object or buffer.

    Args:
        f_or_buffer: Either a `bytes` object or a file-like object.
        address (int): Initial address of the first instruction.
        count (int): Maximum number of instructions to emit. Defaults to infinity.
    """
    f = f_or_buffer if isinstance(f_or_buffer, io.BufferedIOBase) else BytesIO(f_or_buffer)
    i = 0
    while i < count:
        ins = f.read(2)
        if len(ins) != 2:  # Break if no more to read
            break
        ins = int.from_bytes(ins, 'little')
        emit = None
        op = (ins >> 13) & 0b111
        if op == 0b000:
            rd = Reg(ins & 0b111)
            rs = Reg((ins >> 3) & 0b111)
            if (ins >> 11) & 0b11111 == 0b00011:  # THUMB.2
                op = (ins >> 9) & 0b11
                imm = (ins >> 6) & 0b111
                rn = Reg(imm)
                if op == 0:
                    op, nn = Opcode.add, rn
                elif op == 1:
                    op, nn = Opcode.sub, rn
                elif op == 2:
                    op, nn = Opcode.add, imm
                elif op == 3:
                    op, nn = Opcode.sub, imm
                emit = Thumb2(op, address, rd, rs, nn)
            else:  # THUMB.1
                op = (ins >> 11) & 0b11
                offset = (ins >> 6) & 31
                if op == 0:
                    op = Opcode.lsl
                elif op == 1:
                    op = Opcode.lsr
                elif op == 2:
                    op = Opcode.asr
                emit = Thumb1(op, address, rd, rs, offset)
        elif op == 0b001:  # THUMB.3
            op = (ins >> 11) & 0b11
            rd = (ins >> 8) & 0b111
            imm = ins & 0xff
            if op == 0:
                op = Opcode.mov
            elif op == 1:
                op = Opcode.cmp
            elif op == 2:
                op = Opcode.add
            else:
                op = Opcode.sub
            emit = Thumb3(op, address, Reg(rd), imm)
        elif op == 0b010:
            op = (ins >> 10) & 0b111
            if op == 0b000:  # THUMB.4
                op = (ins >> 6) & 0b1111
                rs = Reg((ins >> 3) & 0b111)
                rd = Reg(ins & 0b111)
                table = [Opcode.AND, Opcode.eor, Opcode.lsl, Opcode.lsr,
                         Opcode.asr, Opcode.adc, Opcode.sbc, Opcode.ror,
                         Opcode.tst, Opcode.neg, Opcode.cmp, Opcode.cmn,
                         Opcode.orr, Opcode.mul, Opcode.bic, Opcode.mvn]
                op = table[op]
                emit = Thumb4(op, address, rd, rs)
            elif op == 0b001:  # THUMB.5
                op = (ins >> 8) & 0b11
                msbd = (ins >> 7) & 1
                msbs = (ins >> 6) & 1
                rs = Reg((ins >> 3) & 0b111 | (msbs << 3))
                rd = Reg(ins & 0b111 | (msbd << 3))
                if op < 3 and (msbd or msbs):  # Either msbd or msbs must be set
                    if op == 0:
                        op = Opcode.add
                    elif op == 1:
                        op = Opcode.cmp
                    else:
                        op = Opcode.mov
                    emit = Thumb5(op, address, rd, rs)
                elif op == 3 and not msbd:  # BX must have msbd clear
                    emit = Thumb5(Opcode.bx, address, rd, rs)
            elif op == 0b010 or op == 0b011:  # THUMB.6
                rd = Reg((ins >> 8) & 0b111)
                imm = ins & 0xff
                emit = Thumb6(Opcode.ldr, address, rd, imm)
            else:
                rd = Reg(ins & 0b111)
                rb = Reg((ins >> 3) & 0b111)
                ro = Reg((ins >> 6) & 0b111)
                op = (ins >> 10) & 0b11
                if (ins >> 9) & 1 == 0:  # THUMB.7
                    if op == 0:
                        op = Opcode.STR
                    elif op == 1:
                        op = Opcode.strb
                    elif op == 2:
                        op = Opcode.ldr
                    else:
                        op = Opcode.ldrb
                else:  # THUMB.8
                    if op == 0:
                        op = Opcode.strh
                    elif op == 1:
                        op = Opcode.ldsb
                    elif op == 2:
                        op = Opcode.ldrh
                    else:
                        op = Opcode.ldsh
                emit = Thumb78(op, address, rd, rb, ro)
        elif op == 0b011:  # THUMB.9
            op = (ins >> 11) & 0b11
            if op == 0:
                op = Opcode.STR
            elif op == 1:
                op = Opcode.ldr
            elif op == 2:
                op = Opcode.strb
            else:
                op = Opcode.ldrb
            rd = Reg(ins & 0b111)
            rb = Reg((ins >> 3) & 0b111)
            imm = (ins >> 6) & 31
            emit = Thumb910(op, address, rd, rb, imm)
        elif op == 0b100:
            if (ins >> 12) & 1 == 0:  # THUMB.10
                rd = Reg(ins & 0b111)
                rb = Reg((ins >> 3) & 0b111)
                imm = (ins >> 6) & 31
                if (ins >> 11) & 1:
                    op = Opcode.ldrh
                else:
                    op = Opcode.strh
                emit = Thumb910(op, address, rd, rb, imm)
            else:  # THUMB.11
                rd = Reg((ins >> 8) & 0b111)
                imm = ins & 0xff
                op = Opcode.ldr if (ins >> 11) & 1 else Opcode.STR
                emit = Thumb11(op, address, rd, imm)
        elif op == 0b101:
            if (ins >> 12) & 1 == 0:  # THUMB.12
                rd = Reg((ins >> 8) & 0b111)
                imm = ins & 0xff
                op = Opcode.add
                rs = Reg.sp if (ins >> 11) & 1 else Reg.pc
                emit = Thumb12(op, address, rd, rs, imm)
            elif (ins >> 8) == 0b10110000:  # THUMB.13
                imm = ins & 0x7f
                op = Opcode.sub if (ins >> 7) & 1 else Opcode.add
                emit = Thumb13(op, address, imm)
            elif (ins >> 9) & 0b11 == 0b10:  # THUMB.14
                op = (ins >> 11) & 1
                rlist = ins & 0xff
                if op:
                    op = Opcode.pop
                    rlist |= (1 << 15) if (ins >> 8) & 1 else 0
                else:
                    op = Opcode.push
                    rlist |= (1 << 14) if (ins >> 8) & 1 else 0
                emit = Thumb14(op, address, rlist)
            else:  # TODO: Add BKPT instruction?
                pass
        elif op == 0b110:
            op = (ins >> 12) & 0b1111
            if op == 0b1100:  # THUMB.15
                rb = Reg((ins >> 8) & 0b111)
                rlist = ins & 0xff
                op = Opcode.ldm if (ins >> 11) & 1 else Opcode.stm
                emit = Thumb15(op, address, rb, rlist)
            elif op == 0b1101:  # THUMB.16
                imm = ins & 0xff
                op = (ins >> 8) & 0b1111
                table = [Opcode.beq, Opcode.bne, Opcode.bcs, Opcode.bcc,
                         Opcode.bmi, Opcode.bpl, Opcode.bvs, Opcode.bvc,
                         Opcode.bhi, Opcode.bls, Opcode.bge, Opcode.blt,
                         Opcode.bgt, Opcode.ble]
                if op < 0xe:
                    op = table[op]
                    emit = Thumb1618(op, address, imm)
                elif op == 0xf:  # THUMB.17
                    emit = Thumb17(Opcode.swi, address, ins & 0xff)
        elif op == 0b111:
            op = (ins >> 11) & 0b11111
            if op == 0b11100:  # THUMB.18
                imm = ins & 0x7ff
                emit = Thumb1618(Opcode.b, address, imm)
            elif op == 0b11110:  # THUMB.19
                upper = (ins & 0x7ff) << 11
                b = f.read(2)
                dst = int.from_bytes(b, 'little')
                if b and (dst >> 11) == 31:
                    lower = dst & 0x7ff
                    offset = signed(upper | lower, 22)
                    target = address + 4 + (offset << 1)
                    emit = Thumb19(Opcode.bl, address, target)
                else:  # Seek back before the read
                    f.seek(-len(b), 1)
            else:  # TODO: Partial BL's are legal (See GBATEK Thumb.19)
                pass
        if emit is None:
            emit = ThumbIll(Opcode.ill, address, ins)
        address += emit.size
        i += 1
        yield emit


def signed(n, nbits):  # Convert an unsigned n-bit integer into a signed integer
    if n & (1 << nbits-1) == 0:
        return n
    n |= ~(2**nbits-1)
    return n


def thumb_percentage():  # Compute percentage of illegal thumb instructions
    asm = bytearray()
    for i in range(2**16):
        asm.extend(i.to_bytes(2, 'little'))
    count = 0
    for ins in disasm(asm, 0):
        if ins.id == Opcode.ill:
            count += 1
    print(f'{count}/65536 illegal, {count/65536}')


def time_disasm():
    asm = bytearray()
    for i in range(2**16):
        asm.extend(i.to_bytes(2, 'little'))
    asm.extend(asm)
    start = time.time()
    for _ in disasm(asm, 0):
        pass
    end = time.time()-start
    print(f'{end} seconds, {len(asm)/end:.2f} insns/s')


if __name__ == '__main__':
    pass
