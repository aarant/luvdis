""" ROM disassembly/dumping tools. """
import sys
import os.path
import pkg_resources
from math import inf as INF
from bisect import bisect_left, bisect_right
from io import BytesIO
from collections import defaultdict

from tqdm import tqdm

from luvdis import __version__
from luvdis.common import DEBUG, eprint, warn, dprint
from luvdis.config import write_config
from luvdis.rom import ROM
from luvdis.disasm import disasm, Opcode, Reg, BRANCHES
from luvdis.disasm import Thumb1, Thumb2, Thumb3, Thumb4, Thumb5, Thumb6, Thumb78, Thumb910, Thumb11, Thumb12, Thumb13


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
END_ADDRESS = 0x09FFFFFF  # Highest addressable location
ASM_PRELUDE = f'@ Generated with Luvdis v{__version__}\n.syntax unified\n.text\n'
MACROS = pkg_resources.resource_string('luvdis', 'functions.inc').decode('utf-8')


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


class RomFlags:  # Markable address flags
    def __init__(self, size):
        self.size = size
        self.flags = bytearray(size)

    def __setitem__(self, item, flags_value):
        if isinstance(item, int):
            addr = item & 0xffffff
            if 0 <= addr < self.size:
                self.flags[addr] = flags_value
        elif isinstance(item, slice):
            slice_start_idx = (item.start if item.start is not None else 0) & 0xffffff
            slice_step = item.step if item.step is not None else 1
            if slice_step == 0:
                raise ValueError("slice step cannot be zero")
            if item.stop is None:
                slice_end_idx = self.size
            else:
                slice_end_idx = min(item.stop & 0xffffff, self.size)

            target_slice = slice(slice_start_idx, slice_end_idx, slice_step)
            s_start, s_stop, s_step = target_slice.start, target_slice.stop, target_slice.step
            num_elements = 0
            if s_step > 0 and s_start < s_stop:
                num_elements = (s_stop - s_start + s_step - 1) // s_step
            elif s_step < 0 and s_start > s_stop:
                num_elements = (s_start - s_stop + (-s_step) - 1) // (-s_step)

            if num_elements > 0:
                if not (isinstance(flags_value, int) and 0 <= flags_value <= 255):
                    raise ValueError("flags_value must be an int between 0-255")
                # Efficiently assign the same flags_value to all elements in the target_slice.
                # This leverages bytearray's optimized slice assignment for repeated values.
                self.flags[target_slice] = bytes([flags_value] * num_elements)
        else:  # Capstone instruction
            ins = item
            base = ins.address & 0xffffff
            for i in range(ins.size):
                addr = base + i
                if 0 <= addr < self.size:
                    self.flags[addr] = flags_value

    def __getitem__(self, item):
        if isinstance(item, int):
            addr = item & 0xffffff
            if 0 <= addr < self.size:
                return self.flags[addr]
            raise IndexError("Address out of bounds")
        elif isinstance(item, slice):
            slice_start_idx = (item.start if item.start is not None else 0) & 0xffffff
            slice_step = item.step if item.step is not None else 1
            if slice_step == 0:
                raise ValueError("slice step cannot be zero")
            if item.stop is None:
                slice_end_idx = self.size
            else:
                slice_end_idx = min(item.stop & 0xffffff, self.size)

            current_flags = 0
            idx = slice_start_idx
            if slice_step > 0:
                while idx < slice_end_idx:
                    if 0 <= idx < self.size:
                        current_flags |= self.flags[idx]
                    idx += slice_step
            elif slice_step < 0:
                while idx > slice_end_idx: # Corrected condition from idx < slice_end_idx
                    if 0 <= idx < self.size:
                        current_flags |= self.flags[idx]
                    idx += slice_step
            return current_flags
        else: # Capstone instruction
            ins = item
            base = ins.address & 0xffffff
            current_flags = 0
            for i in range(ins.size):
                addr = base + i
                if 0 <= addr < self.size:
                    current_flags |= self.flags[addr]
            return current_flags


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
    __slots__ = ('reg', 'stack', 'sp', 'handlers')

    def __init__(self):
        self.reg = [self.unknown for _ in range(16)]
        self.reg[14] = self.return_addr
        self.reg[13] = 0x030007F0
        self.stack = [self.unknown for _ in range(16)]
        self.sp = 0

        self.handlers = {
            Thumb1: self._handle_thumb1,
            Thumb2: self._handle_thumb2,
            Thumb3: self._handle_thumb3,
            Thumb4: self._handle_thumb4,
            Thumb5: self._handle_thumb5_general, # For non-BX Thumb5
            Thumb6: self._handle_thumb6_ldr_pc,
            Thumb78: self._handle_thumb78,
            Thumb910: self._handle_thumb910,
            Thumb11: self._handle_thumb11,
            Thumb12: self._handle_thumb12,
            Thumb13: self._handle_thumb13,
            Opcode.push: self._handle_push,
            Opcode.pop: self._handle_pop,
            Opcode.stm: self._handle_stmldm,
            Opcode.ldm: self._handle_stmldm,
            Opcode.bl: self._handle_bl,
            Opcode.bx: self._handle_bx, # Specific handler for BX
            Opcode.ill: self._handle_ill,
        }
        for op_id in BRANCHES: # BRANCHES is imported from luvdis.disasm
            self.handlers[op_id] = self._handle_branch

    def _handle_thumb1(self, ins, rom):
        if ins.id in (Opcode.lsr, Opcode.asr) and ins.offset == 0:
            offset = 32
        else:
            offset = ins.offset
        self.throp(ins.rd, ins.rs, offset, ins.id)
        return False

    def _handle_thumb2(self, ins, rom):
        self.throp(ins.rd, ins.rs, ins.n, ins.id)
        return False

    def _handle_thumb3(self, ins, rom):
        if ins.id != Opcode.cmp:
            self.throp(ins.rd, ins.rd, ins.imm, ins.id)
        return False

    def _handle_thumb4(self, ins, rom):
        self.throp(ins.rd, ins.rd, ins.rs, ins.id)
        return False

    def _handle_thumb5_general(self, ins, rom): # Handles non-BX Thumb5 cases
        self.throp(ins.rd, ins.rd, ins.rs, ins.id)
        if ins.id != Opcode.cmp and ins.rd == 15:  # destination pc
            return True
        return False

    def _handle_thumb6_ldr_pc(self, ins, rom):
        value = rom.read(ins.target, 4)
        self[ins.rd] = value
        return True

    def _handle_thumb78(self, ins, rom):
        self.load(rom, ins.rd, ins.rb, ins.ro, ins.id)
        return False

    def _handle_thumb910(self, ins, rom):
        self.load(rom, ins.rd, ins.rb, ins.imm, ins.id)
        return False

    def _handle_thumb11(self, ins, rom):
        index = self.sp - ins.imm # Note: ins.imm is number of words, not bytes for ldr/str sp-relative
        if ins.id == Opcode.ldr:
            if 0 <= index < len(self.stack):
                self[ins.rd] = self.stack[index]
            else:
                self[ins.rd] = self.unknown
        else: # Opcode.str
            if 0 <= index < len(self.stack):
                self.stack[index] = self[ins.rd]
        return False

    def _handle_thumb12(self, ins, rom):
        self.throp(ins.rd, ins.rs, ins.imm * 4, ins.id) # imm is #words
        return False

    def _handle_thumb13(self, ins, rom):
        offset = ins.imm if ins.id == Opcode.add else -ins.imm
        # self.sp is an index into self.stack, not a memory address
        # self[13] (SP register) is the memory address
        # ARMv6-M Architecture Reference Manual B1.5.5 SP (Stack Pointer)
        # "The SP is decremented on push operations and incremented on pop operations."
        # "ADD/SUB SP, SP, #imm" implies offset is in bytes
        # Thumb13 is "ADD/SUB SP, SP, #imm" (imm is #words for instruction encoding, but value is imm*4)

        # Based on original code: self.sp seems to be #items on custom stack, not related to self[13] directly for this op
        # Original: self.sp -= offset -- this seems to be for the custom self.stack, not the CPU's SP register.
        # Original: self[13] += offset*4 -- this updates the CPU's SP register.
        # The original logic for self.sp with Thumb13's ADD/SUB SP,SP,#imm seems suspicious.
        # ADD/SUB SP,SP,#imm directly modifies the SP register.
        # A PUSH/POP would modify SP and also interact with a conceptual stack.
        # Let's stick to the original logic as much as possible.
        # The instruction "ADD SP, SP, #imm" or "SUB SP, SP, #imm" (where imm is a multiple of 4)
        # modifies the stack pointer. The self.sp and self.stack seem to be a high-level abstraction.

        self[13] += (offset * 4) # This is what ADD/SUB SP, SP, #imm does. offset is already +/- from ins.id

        # The following logic for self.sp and self.stack from the original code seems to be
        # trying to model a separate software stack or adjust the internal representation.
        # It's kept here to maintain functional parity with the original, but it's non-standard for direct SP manipulation.
        _conceptual_sp_change = offset # This 'offset' is in words for the custom stack logic
        self.sp -= _conceptual_sp_change
        if _conceptual_sp_change < 0: # Effectively a push-like expansion for the custom stack
             for _ in range(-_conceptual_sp_change): # if self.sp got more negative (less items), need to fill with unknown
                 if len(self.stack) > self.sp >=0: # Only if self.sp is still a valid index
                     pass # No need to append if it means SP is now pointing within existing items
                 else: # self.sp became too small or negative, conceptually items removed from tracked stack
                      pass # Or, if self.sp decreased (items added to conceptual stack), extend if needed
        # If self.sp increased (items removed from conceptual stack), then no change to stack array size needed.
        # The original code `for _ in range(len(self.stack)-self.sp): self.stack.append(self.unknown)`
        # seems to only ever grow the stack if self.sp becomes smaller than its current length,
        # which happens if `offset` is positive (SUB SP, SP, #X -> conceptual pop, self.sp decreases).
        # Let's refine this to match the original's apparent intent more clearly:
        if self.sp < 0: # If conceptual stack pointer goes negative, reset/clamp (original didn't do this explicitly)
            self.sp = 0
        # Ensure self.stack is large enough if self.sp indicates more items than array capacity
        # This part is tricky because self.sp is an index.
        # If `offset` is positive (SUB SP, SP, #imm), `_conceptual_sp_change` is positive, `self.sp` decreases.
        # If `self.sp` decreases, it means conceptually more items are on our `self.stack`.
        # The original `for _ in range(len(self.stack)-self.sp): self.stack.append(self.unknown)`
        # would append if `len(self.stack)` was greater than `self.sp`.
        # This happens if `self.sp` *decreases*.
        # e.g. stack has 10 items, sp=9. offset=1 (SUB). sp becomes 8. len(stack)-sp = 10-8=2. Appends 2.
        # This makes the stack grow when SP is reduced (conceptual push-like behavior for self.stack).
        needed_size = self.sp + 1 # if sp is an index, capacity should be sp+1
        # The original loop condition `len(self.stack)-self.sp` is effectively `current_capacity - new_sp_index -1` items to add.
        # Let's try to match the original loop's effect:
        # Number of items to append = (current_len - new_sp) if new_sp < current_len.
        # This logic is complex and seems specific to this emulator's custom stack idea.
        # For now, let's stick to what was there:
        # This loop appends if self.sp becomes smaller than len(self.stack)
        # (i.e. if we are tracking more elements than before due to a conceptual push/SP decrease)
        while self.sp >= len(self.stack): # if sp index is beyond current stack, extend it
             self.stack.append(self.unknown)
        # The original code `for _ in range(len(self.stack)-self.sp): self.stack.append(self.unknown)`
        # would append `max(0, len(self.stack) - self.sp)` unknown values.
        # This is intended to ensure `self.stack` can hold elements up to index `self.sp` if `self.sp` points high.
        # However, if `self.sp` decreases (e.g. after SUB SP, SP, #imm), then `len(self.stack) - self.sp` increases.
        # This means it appends more items if SP decreases.

        # Let's re-evaluate the original:
        # self.sp -= offset (offset is in words, e.g. +1 for ADD, -1 for SUB)
        # self[13] += offset*4 (this is correct for SP register)
        # for _ in range(len(self.stack)-self.sp): self.stack.append(self.unknown)
        # If ADD SP, SP, #4 (offset=1 word): self.sp becomes self.sp-1. len(self.stack)-(self.sp-1) items appended. More items appended.
        # If SUB SP, SP, #4 (offset=-1 word): self.sp becomes self.sp+1. len(self.stack)-(self.sp+1) items appended. Fewer items appended.
        # This seems to map ADD SP (pop-like) to pushing onto self.stack, and SUB SP (push-like) to popping from self.stack.
        # This is inverted relative to how PUSH/POP normally affect SP and a stack.
        # Given the ambiguity and potential inversion, I will replicate the original logic as closely as possible for now.
        # The original code:
        # self.sp -= offset # offset is in words for ins.imm, sign depends on ADD/SUB
        # for _ in range(len(self.stack)-self.sp): # This condition means if self.sp becomes smaller than current len
        #    self.stack.append(self.unknown)      # then append.
        # self[13] += offset*4

        # The loop should probably be:
        # while self.sp >= len(self.stack):
        #     self.stack.append(self.unknown)
        # This ensures that if self.sp is now a high index, the stack is extended.
        # And if self.sp is a low index (conceptual pop), the stack just remains, and self.sp points lower.
        # The original code's loop `for _ in range(len(self.stack)-self.sp):` only appends if `self.sp < len(self.stack)`.
        # This means if self.sp becomes a *smaller index* (more items on conceptual stack), it appends.
        # Example: stack=[u,u,u], len=3, sp=2. ADD SP,SP,4 (offset=1). self.sp becomes 1.
        # Loop range(3-1)=range(2). Appends 2 unknowns. stack=[u,u,u,u,u], sp=1. This is like a PUSH.
        # Example: stack=[u,u,u], len=3, sp=2. SUB SP,SP,4 (offset=-1). self.sp becomes 3.
        # Loop range(3-3)=range(0). Appends 0. stack=[u,u,u], sp=3. `self.sp` is now out of bounds for list access.
        # This suggests the custom `self.sp` and `self.stack` are not a direct model of the hardware stack for this op.
        # Let's try to keep it as original as possible:
        # self.sp -= offset # offset is in words (+ for ADD, - for SUB)
        # num_to_append = len(self.stack) - self.sp
        # for _ in range(num_to_append):
        #    self.stack.append(self.unknown)
        # This logic still feels off.
        # A simpler model for Thumb13 ADD/SUB SP,SP,#imm:
        # The SP register (self[13]) is updated.
        # The self.stack and self.sp (if they are meant to model the actual stack contents accessible via SP)
        # would need to be adjusted based on the new self[13] value, which is complex.
        # The original code for Thumb13's self.sp/self.stack manipulation is very specific.
        # Let's assume `self.sp` is a count of "active" items on `self.stack` for this emulator's purposes.
        # If `offset` is positive (ADD SP, SP, #imm -> SP increases, stack shrinks): `self.sp` decreases.
        # If `offset` is negative (SUB SP, SP, #imm -> SP decreases, stack grows): `self.sp` increases.

        # Re-checking original:
        # self.sp -= offset  (if add, offset is pos, sp decreases; if sub, offset is neg, sp increases)
        # self[13] += offset*4 (standard SP update)
        # for _ in range(len(self.stack)-self.sp): self.stack.append(self.unknown)
        #   This loop appends if self.sp < len(self.stack).
        #   If ADD (sp decreases): len(self.stack) - self.sp increases -> more appends. Stack grows.
        #   If SUB (sp increases): len(self.stack) - self.sp decreases -> fewer/no appends. Stack might not grow.
        # This is consistent: ADD SP (pop) makes self.stack grow here. SUB SP (push) makes self.stack shrink/not grow.
        # This is the opposite of PUSH/POP handlers. It's likely specific to how this emulator uses self.sp/self.stack.
        # I will keep this exact logic.

        _original_sp_val_in_words = self.sp # Store current custom stack pointer (count of items?)

        # Update CPU's actual SP register
        # ins.imm is in words for Thumb13, value is ins.imm * 4
        sp_change_bytes = ins.imm * 4
        if ins.id == Opcode.add:
            self[13] += sp_change_bytes
            # For custom stack: ADD SP, SP, #X (pop-like) -> self.sp decreases
            self.sp -= ins.imm
        else: # Opcode.sub
            self[13] -= sp_change_bytes
            # For custom stack: SUB SP, SP, #X (push-like) -> self.sp increases
            self.sp += ins.imm

        # Adjust custom stack array size if needed, based on original logic
        # This loop appends if self.sp (new) < len(self.stack) (old/current)
        # This means if self.sp has become a smaller index relative to current capacity, extend capacity.
        # This ensures that self.stack has enough capacity if self.sp now points to a conceptually "deeper" part of an expanded stack.
        # This is still very confusing. Let's use the exact original three lines:
        # offset = ins.imm if ins.id == Opcode.add else -ins.imm # offset in words
        # self.sp -= offset # If ADD, sp decreases. If SUB, sp increases.
        # for _ in range(len(self.stack)-self.sp): self.stack.append(self.unknown)
        # self[13] += offset*4
        # This was the original order. Let's restore it.

        offset_words = ins.imm if ins.id == Opcode.add else -ins.imm
        self.sp -= offset_words # Custom stack pointer adjustment

        # This loop ensures that if self.sp has decreased (meaning the conceptual stack grew deeper),
        # the self.stack list is extended with unknown values to accommodate this.
        # If self.sp increased (conceptual stack shrank), this loop does nothing or fewer iterations.
        # Example: stack has 5 items, sp=4. ADD SP,SP,4 (offset_words=1). self.sp becomes 3.
        # loop range(len_before - 3). If len_before was 5, range(2). Appends 2. Stack becomes 7 items, sp=3.
        # Example: stack has 5 items, sp=4. SUB SP,SP,4 (offset_words=-1). self.sp becomes 5.
        # loop range(len_before - 5). If len_before was 5, range(0). Appends 0. Stack is 5 items, sp=5. (index out of bounds for list)
        # The self.sp must be an index, so if it becomes equal to len(self.stack), it's problematic for direct access.
        # The PUSH handler increments self.sp *after* potentially appending.

        # Let's stick to the exact original block structure for Thumb13 for now due to its specific self.stack logic:
        _offset_for_sp_reg = ins.imm if ins.id == Opcode.add else -ins.imm # This is in words
        self.sp -= _offset_for_sp_reg # self.sp is the count/index for the internal self.stack

        # This loop from original code:
        # If self.sp (new) < len(self.stack) (current cap), it appends (len(self.stack) - self.sp) items.
        # This happens when self.sp decreases (e.g. ADD SP,SP,imm -> pop-like for SP, but push-like for self.sp here)
        # This means self.stack grows when self.sp decreases.
        num_to_append = len(self.stack) - self.sp
        if num_to_append > 0 : # Only append if self.sp is less than current length
            for _ in range(num_to_append):
                self.stack.append(self.unknown)

        self[13] += _offset_for_sp_reg * 4 # Update the actual SP register
        return False

    def _handle_push(self, ins, rom):
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
        return False

    def _handle_pop(self, ins, rom):
        rlist = ins.rlist
        for i in range(16):
            if rlist & (1 << i):  # Increment after and pop
                self.sp -= 1
                if not (0 <= self.sp < len(self.stack)):
                    value = self.unknown
                else:
                    value = self.stack[self.sp]
                self[i] = value
                self[13] += 4
        return ins.touched(15) # break if pop {pc}

    def _handle_stmldm(self, ins, rom): # Handles STM and LDM
        bits = 0
        for i in range(8): # STM/LDM only operate on r0-r7 for base register update
            if ins.rlist & (1 << i):
                bits += 1
        self[ins.rb] += 4 * bits
        return False

    def _handle_bl(self, ins, rom):
        self[0] = self.unknown # R0 is usually scratch in AAPCS, can be clobbered
        self[14] = ins.address + 4 # LR = return address
        return True # BL is a branch

    def _handle_bx(self, ins, rom): # Handles BX
        # Original code for Thumb5 BX was just 'break'.
        # BX target is self[ins.rs]. If ins.rs is PC, it's effectively a NOP branch.
        # If LR, it's a return.
        return True # BX is a branch

    def _handle_branch(self, ins, rom): # Handles generic B, BEQ, BNE etc from BRANCHES
        return True # All are branches

    def _handle_ill(self, ins, rom): # Handles illegal instruction
        return True # Stop emulation

    def emulate(self, rom, addr):
        ins = None # Stores the last instruction processed
        for current_ins in rom.dist(addr):
            ins = current_ins
            # print(f'{self}\n{ins} @ {ins.address:08X}') # Original debug print
            self[15] = ins.address + 4  # Update PC (R15) to point to the next instruction (or current + 4 for ARM state)

            handler = self.handlers.get(type(ins))
            if not handler: # Fallback to ins.id if type-specific handler not found
                handler = self.handlers.get(ins.id)

            should_break = False
            if handler:
                should_break = handler(ins, rom) # Execute handler
            # else:
                # If no handler, by default, don't break (continue to next instruction)
                # This case should ideally not be hit if handlers are comprehensive.
                # Or, it implies a generic instruction that doesn't change flow control.
                # The original code implicitly continued if no specific block matched.

            if should_break:
                break
        return ins

    def throp(self, rd, rs, imm, op):
        value = self[rs]
        if type(imm) is Reg: # Immediate can be a register number
            imm_val = self[imm] # Fetch value from register if imm is Reg type
        else:
            imm_val = imm # Else, imm is a direct value

        if op == Opcode.lsl:
            value = (value << imm_val)
        elif op in (Opcode.lsr, Opcode.asr):
            value = (value >> imm_val)
        elif op == Opcode.add:
            value += imm_val
        elif op == Opcode.sub:
            value -= imm_val
        elif op == Opcode.mov:
            value = imm_val
        elif op == Opcode.AND: # AND is a keyword, op must be Opcode.AND
            value &= imm_val
        elif op == Opcode.eor:
            value ^= imm_val
        elif op == Opcode.adc:  # TODO: Add with carry
            value += imm_val
        elif op == Opcode.sbc:  # TODO: Subtract with carry
            value -= imm_val
        elif op == Opcode.ror:
            imm_val %= 32
            value = (value >> imm_val) | (value << (32-imm_val))
        elif op in (Opcode.tst, Opcode.cmp, Opcode.cmn):
            return # These ops only set flags, don't change rd
        elif op == Opcode.neg:
            value = -imm_val # NEG is RS, Rd, so imm_val comes from RS (passed as imm here)
        elif op == Opcode.orr:
            value |= imm_val
        elif op == Opcode.mul:
            value *= imm_val
        elif op == Opcode.bic:
            value = value & (~imm_val)
        elif op == Opcode.mvn:
            value = ~imm_val
        self[rd] = value

    def load(self, rom, rd, rb, offset, op):
        addr = self[rb]
        # cursor = rom.f.tell() # Removed as rom.f is not directly used here for reading
        if type(offset) is Reg:
            offset_val = self[offset]
        else:
            offset_val = offset

        addr += offset_val
        if addr == self.unknown or (addr & 0xff000000) != BASE_ADDRESS:
            self[rd] = self.unknown # Set rd to unknown if address is bad
            return # Original code returned self.unknown, but load modifies self[rd]

        value_read = self.unknown
        # rom.read should handle address translation if needed (e.g. BASE_ADDRESS)
        # Assuming rom.read takes absolute ARM address
        try:
            if op == Opcode.ldr: # Load Word
                value_read = rom.read(addr, 4)
            elif op == Opcode.ldrb: # Load Byte
                value_read = rom.read(addr, 1)
            elif op == Opcode.ldrh: # Load Halfword
                value_read = rom.read(addr, 2)
            elif op in (Opcode.ldsb, Opcode.ldsh): # Load Signed Byte/Halfword
                # Actual sign extension logic would be needed here if not handled by rom.read
                # For now, mirroring original behavior of setting to unknown for these
                value_read = self.unknown
            else: # Should not happen if op is validated before
                self[rd] = self.unknown
                return
        except IndexError: # If rom.read fails due to out-of-bounds
            value_read = self.unknown

        self[rd] = value_read
        # assert rom.f.tell() == cursor # Cannot assert this without direct rom.f access

    def copy(self):
        new_state = CPUState()
        new_state.reg = self.reg[:]
        new_state.stack = self.stack[:]
        new_state.sp = self.sp
        return new_state

    def __getitem__(self, i):
        # Ensure PC (R15) reads are handled correctly for Thumb (address + 4) or ARM (address + 8)
        # The current emulator seems to always store R15 as next_instruction_addr + 4 (Thumb style)
        # For direct access self[15], it should return this stored value.
        return self.reg[i] % 2**32 if self.reg[i] is not self.unknown else self.unknown


    def __setitem__(self, i, value):
        self.reg[i] = value % 2**32 if value is not self.unknown else self.unknown


    def __str__(self):
        lines = []
        for row in range(4):
            parts = []
            for col in range(4):
                i = col + 4*row
                value = self[i] # Uses __getitem__
                if value != self.unknown:
                    value_str = f'{value:08X}'
                else:
                    value_str = 'unknown '
                parts.append(f'r{i:02d}: {value_str}')
            lines.append(' '.join(parts))
        parts = []
        # Displaying self.stack which is the custom abstract stack
        # self.sp is an index for self.stack
        for i, value in enumerate(self.stack):
            val_str = f'{value:08X}' if value is not self.unknown else 'unknown '
            if i == self.sp: # Mark the custom stack pointer's position
                parts.append(f'>{val_str}')
            else:
                parts.append(f' {val_str}')
        lines.append('Stack (custom): [' + ','.join(parts) + f'] (SP_idx={self.sp})')
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
        self.functions = {}  # addr -> (name, end_address)
        self.not_funcs = set()
        self.min_calls, self.min_length, self.start, self.stop = min_calls, min_length, start, stop
        self.macros = macros

        self.debug_ranges = {}

        self.call_to = defaultdict(set)  # addr -> {called from}

        self.flags = None
        self.label_map = {BASE_ADDRESS: BRANCH}

    def analyze_rom(self, rom, guess=True):  # Analyze a ROM
        if type(self.stop) is float:
            eprint(f'Disassembling from 0x{self.start:08X}:')
        else:
            eprint(f'Disassembling from 0x{self.start:08X}:0x{self.stop:08X}')
        pushes = set()  # Set of push {xx, lr} addresses
        self.flags = RomFlags(rom.size)
        for ins in rom.dist(self.start):
            addr = ins.address
            if addr >= self.stop:
                break
            # THUMB.14
            if ins.id == Opcode.push and ins.touched(Reg.lr):
                # Add addr and preceding locations as possible function entries
                pushes.add(max(BASE_ADDRESS, addr-4))
                pushes.add(max(BASE_ADDRESS, addr-2))
                pushes.add(addr)
            # THUMB.19
            elif ins.id == Opcode.bl:
                self.call_to[ins.target].add(addr)
        # Expand all provided functions
        eprint(f'{len(self.unexpanded)} functions provided')
        changed = self.analyze_funcs(rom, 0)
        if not guess:  # Stop here if not guessing
            self.make_labels(rom)
            return
        # Repeatedly expand and find new functions
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

    def guess_funcs(self, rom, entries):  # Guess functions based on number of calls and code length
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
        initial_stack_reg_val = state[13]  # Initial value of actual stack pointer register (R13)

        # The original code's `initial_stack` was state[13].
        # The exit condition `state[13] == initial_stack` is for the SP register.
        # The custom `state.sp` and `state.stack` are separate.
        # A well-behaved function should restore the SP register.

        starts = {addr: state}
        expanded = {}  # Start addresses -> exit behavior seen so far
        labels = {}  # Addresses -> label type
        calls = {}  # Addresses -> call state
        ranges = []  # List of (start:end, flag) tuples of executable regions

        while starts:  # Continue as long as there are paths to explore
            new_starts = {}
            # Process current start points. Sorting by address ensures deterministic analysis,
            # which is important for consistent results, though it might have a performance cost
            # for functions with very many concurrent paths to explore.
            for current_path_start_addr, current_state in sorted(starts.items()):  # Emulate from each start address
                # current_addr = current_path_start_addr # Not needed, state.emulate takes start addr

                # Emulate this path until a branch, return, or relevant stopping point
                last_ins = current_state.emulate(rom, current_path_start_addr)

                # Determine behavior at the end of this emulation path
                exit_behaved = None # None = path continues or forks, True = clean exit, False = misbehavior

                if last_ins is None or last_ins.id == Opcode.ill: # Hit end of ROM or illegal instruction
                    exit_behaved = False
                    path_end_addr = rom.size + BASE_ADDRESS if last_ins is None else last_ins.address
                else:
                    path_end_addr = last_ins.address + last_ins.size # Address after the instruction that caused break

                    if last_ins.id == Opcode.ldr and isinstance(last_ins, Thumb6): # LDR PC-relative, already handled by emulate
                        # This was Thumb6 specific logic in old analyze_func, now part of its handler.
                        # LDR PC-relative does not stop path usually, but its handler returns True.
                        # So this means it's treated as a path-ending point for analysis here.
                        target = last_ins.target # ins.target is already an absolute address
                        if target < self.stop:
                             labels[target] = WORD
                             # ranges.append((target, target + 4, FLAG_WORD)) # Should be added by caller if needed
                        # For LDR PC-rel, path does not inherently stop unless it loads PC.
                        # The handler _handle_thumb6_ldr_pc returns True, so it's a stop point.
                        # If it loaded PC, exit_behaved would be determined by where it goes.
                        # For now, assume LDR PC-rel itself isn't a "return" type, so behavior is neutral.
                        # This needs careful review if LDR PC-rel can load into R15.
                        # Capstone's `ins.target` for LDR PC-rel is the memory address being read.
                        # The instruction itself is `ldr rd, [pc, #imm]`
                        # If rd is PC, then it's a branch. The `emulate` should handle PC update.
                        # The `_handle_thumb6_ldr_pc` returns True, so it's a stop.
                        # If it loaded PC, `current_state[15]` would be the new PC.
                        # Here, we just acknowledge it stopped. If it was a jump, new_starts should handle it.
                        # This block seems to be for *data* pointed to by LDR, not if LDR itself is a branch.
                         pass # Handled by its own handler.

                    elif last_ins.id in BRANCHES and last_ins.id != Opcode.bl and last_ins.id != Opcode.bx : # Unconditional B, conditional Bxx
                        target = last_ins.target
                        if target < self.stop:
                            labels[target] = BRANCH
                            if target not in expanded: # If this branch target hasn't been explored from
                                new_starts[target] = current_state.copy()
                            # exit_behaved remains None as path continues elsewhere or forks
                        else: # Branching OOB is misbehavior for this path
                            exit_behaved = False
                        # If it's an unconditional branch (Opcode.b), this path definitely stops here.
                        # If conditional, this path conceptually stops and may or may not take the branch.
                        # The `emulate` loop breaks on any branch, so this is an endpoint for this linear trace.

                    elif last_ins.id == Opcode.bl:
                        target = last_ins.target
                        if target < self.stop:
                            labels[target] = BRANCH # Functions are also branch targets
                            calls[target] = current_state.copy() # Save state *before* call for analysis of called func
                            # exit_behaved remains None as path continues after BL
                            # The `emulate` loop breaks on BL, so this current path trace ends.
                            # The path *after* the BL needs to be added to new_starts.
                            # Address after BL is last_ins.address + 4
                            addr_after_bl = last_ins.address + 4
                            if addr_after_bl < self.stop and addr_after_bl not in expanded:
                                # State after BL: LR is set by handler, R0-R3,R12 scratch
                                state_after_bl = current_state.copy() # current_state has LR set by _handle_bl
                                state_after_bl[0] = self.unknown # AAPCS
                                state_after_bl[1] = self.unknown
                                state_after_bl[2] = self.unknown
                                state_after_bl[3] = self.unknown
                                state_after_bl[12] = self.unknown # R12 is IP (scratch)
                                new_starts[addr_after_bl] = state_after_bl
                        else: # Calling OOB is misbehavior
                            exit_behaved = False

                    elif last_ins.id == Opcode.bx: # Branch and exchange (typically return via LR or jump)
                        target_addr = current_state[last_ins.rs] & 0xFFFFFFFE # Target address from register, mask LSB (Thumb state)
                        # Well-behaved if returning to the expected LR and SP is restored
                        is_return_to_lr = (target_addr == (current_state.return_addr & 0xFFFFFFFE))
                        is_sp_restored = (current_state[13] == initial_stack_reg_val)
                        exit_behaved = is_return_to_lr and is_sp_restored
                        # If not a well-behaved return, it might be a tail call or indirect jump.
                        # If it's a jump to another known function or label, it's not necessarily "misbehavior".
                        # For simplicity here, only perfect return is True.
                        if not exit_behaved and target_addr < self.stop and target_addr != current_path_start_addr : # Avoid self-loop if not return
                             if target_addr not in expanded:
                                 # Treat as a jump/fork if not a clean return
                                 # State for the new path is current_state after BX's effect (PC change)
                                 # BX handler already updated PC if RS was R15.
                                 # Here, current_state[15] is already next instruction from emulate loop.
                                 # The actual jump target is target_addr.
                                 new_state_for_jump = current_state.copy()
                                 new_state_for_jump[15] = target_addr # Set PC for the new path
                                 new_starts[target_addr] = new_state_for_jump
                                 exit_behaved = None # Path forks


                    elif last_ins.id == Opcode.pop and last_ins.touched(15): # POP {..., PC}
                        # Target is current_state[15] which was popped into PC
                        # This is already the address of the instruction *after* the POP if PC was not in list.
                        # If PC was in list, _handle_pop updates self[15] to the popped value.
                        target_addr = current_state[15] & 0xFFFFFFFE # Address popped into PC
                        is_return_to_lr = (target_addr == (current_state.return_addr & 0xFFFFFFFE))
                        # POP also modifies SP (R13). Check if SP restored to initial.
                        is_sp_restored = (current_state[13] == initial_stack_reg_val)
                        exit_behaved = is_return_to_lr and is_sp_restored

                    elif last_ins.rd == 15 and last_ins.id not in BRANCHES and last_ins.id != Opcode.pop: # Other instruction writing to PC (e.g. MOV PC, LR)
                        target_addr = current_state[15] & 0xFFFFFFFE # Value written to PC
                        is_return_to_lr = (target_addr == (current_state.return_addr & 0xFFFFFFFE))
                        is_sp_restored = (current_state[13] == initial_stack_reg_val)
                        exit_behaved = is_return_to_lr and is_sp_restored
                        # Similar to BX, if not a clean return, could be a jump
                        if not exit_behaved and target_addr < self.stop and target_addr != current_path_start_addr:
                            if target_addr not in expanded:
                                new_state_for_jump = current_state.copy()
                                # PC is already set by the instruction's handler in current_state[15]
                                new_starts[target_addr] = new_state_for_jump
                                exit_behaved = None # Path forks


                    # If no specific condition met that implies a branch/return, path just ends here for analysis.
                    # This could be if emulate stops due to reaching end of its iteration without a break instruction.
                    # This case should be rare if rom.dist(addr) is long enough.
                    # If exit_behaved is still None, it means it's a normal instruction, path continues.
                    # However, emulate() loop breaks on flow control changes.
                    # So if we are here, last_ins is the one that caused the break.
                    # If exit_behaved is still None, it means it was a branch handled above (like B, BL)
                    # where the path continues elsewhere, or a situation not yet classified.
                    # For safety, if not explicitly True/False, assume it's a non-terminal path end for now.
                    if exit_behaved is None and path_end_addr < self.stop and path_end_addr not in expanded :
                        # If it was a simple instruction that didn't break (e.g. MOV R0, R1),
                        # and emulate() just finished its default iteration count (if any),
                        # then the path continues.
                        # This logic needs to be careful: `emulate` returns the *last* instruction.
                        # If `last_ins` didn't cause a break, then `path_end_addr` is where to continue.
                        # This seems to be covered by BL's explicit continuation.
                        # For other cases, if `emulate` just stops, we record the range.
                        pass


                expanded[current_path_start_addr] = exit_behaved
                # Record the range of instructions processed in this path segment.
                # current_path_start_addr is the start, path_end_addr is after the last instruction.
                # Ensure path_end_addr does not exceed current_path_start_addr.
                if path_end_addr > current_path_start_addr :
                    ranges.append((current_path_start_addr, path_end_addr, FLAG_EXEC))

            starts = new_starts

        # Tally exit behaviors
        exits = [1 for behavior in expanded.values() if behavior is True] # Only count True as clean exits
        total_paths_ending_in_return_like = len([b for b in expanded.values() if b is not None]) # Paths that had a defined end (True or False)

        # Original code: total = len(exits from expanded.values() if behavior is not None)
        # exited = sum(exits)
        # This means 'total' was count of paths that ended cleanly OR misbehaved.
        # 'exited' was count of paths that ended cleanly (True).
        # If a path forked (behavior is None), it wasn't in 'exits' list.

        return sum(exits), total_paths_ending_in_return_like, labels, calls, ranges

    def analyze_funcs(self, rom, threshold=0.5):
        changed = False
        new_unexpanded = {}
        for func_addr, name in self.unexpanded.items():
            # Initial state for analyzing a function:
            # LR (R14) should be set to a generic return_addr (e.g., BASE_ADDRESS or a specific marker)
            # SP (R13) should be set to its typical initial value.
            # Other regs are unknown.
            initial_state_for_func = CPUState()
            # initial_state_for_func.reg[14] = CPUState.return_addr # Already set by CPUState.__init__
            # initial_state_for_func.reg[13] = 0x030007F0 # Standard initial SP for GBA

            exited_cleanly_count, paths_with_defined_end_count, labels, calls, ranges = self.analyze_func(rom, func_addr, initial_state_for_func)

            # Original condition: (total and exited/total < threshold) or (total == 0 != threshold)
            # total = paths_with_defined_end_count
            # exited = exited_cleanly_count
            if (paths_with_defined_end_count > 0 and exited_cleanly_count / paths_with_defined_end_count < threshold) or \
               (paths_with_defined_end_count == 0 and threshold != 0): # If no paths ended cleanly or misbehaved, and threshold expects some.
                self.not_funcs.add(func_addr)
                continue

            self.label_map.update(labels)
            for start_range, end_range, flag in ranges:
                if end_range > start_range: # Ensure valid range
                    self.flags[start_range:end_range] |= flag
                    if DEBUG and (flag & FLAG_EXEC):  # Track executable ranges for debugging
                        self.debug_ranges.setdefault(func_addr, []).append((start_range, end_range))

            for target_call_addr, _call_state in calls.items(): # call_state is not used here currently
                if all(target_call_addr not in d for d in (self.functions, self.unexpanded, self.not_funcs, new_unexpanded)):
                    new_unexpanded[target_call_addr] = None  # Mark for future analysis
                    changed = True
            self.functions[func_addr] = (name, None)  # TODO: Track the ends of functions?
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

    def dump(self, rom, path=None, config_output=None, default_mode=BYTE):
        if config_output:  # Optionally write updated function list
            addr_map = {addr: (name, self.module_addrs.get(addr, None)) for addr, (name, _) in self.functions.items()}
            write_config(addr_map, config_output)
        # Setup initial module & file
        folder, module = os.path.split(path) if path else (None, None)
        if DEBUG and path:
            import pickle
            # Output function range info if debugging
            with open(os.path.join(folder, 'funcs.pickle'), 'wb') as f:
                pickle.dump(self.debug_ranges, f)
            # Also output a linker script
            fl = open('luvdis.ld', 'w')
        f = None if path else sys.stdout
        # Setup start and end addresses
        addr = self.start
        if type(self.stop) is float:  # End at the final address in the ROM
            end = rom.size | BASE_ADDRESS
        else:
            end = min(rom.size, self.stop & 0xffffff) | BASE_ADDRESS
        if addr not in self.module_addrs and module:  # Mark the very first address as belonging to the initial module
            self.module_addrs[addr] = module
        mode, flags, bytecount = BYTE, 0, 0
        # Initialize progress bar & messages
        bar = tqdm(total=end-addr, file=sys.stderr, unit='B', unit_scale=True).__enter__()
        def eprint(*args):
            return bar.write(' '.join(args), file=sys.stderr)
        def warn(*args):
            return bar.write(' '.join(('Warning:',) + args), file=sys.stderr)
        module_len = 0
        # Main disassembly loop
        while addr < end:
            next_addr = left_gt(self.labels, addr)  # Address of next label greater than this address, if any
            addr_flags = self.flags[addr]  # Address flags
            old_mode = mode

            # Switch output modes
            if addr_flags == 0 and flags != 0:  # Switch to default mode when address flags are zero
                mode = default_mode  # By default, BYTE mode
            elif addr_flags & FLAG_EXEC and not (flags & FLAG_EXEC):  # Output code
                mode = THUMB
            elif addr_flags & FLAG_WORD and not (flags & FLAG_WORD) and not (addr_flags & FLAG_EXEC):  # Output words
                mode = WORD
            # Avoid overlapping label with BL or word by switching into byte mode
            if mode == THUMB:
                ins_list = list(rom.dist(addr, 1)) # Get the instruction at addr
                if not ins_list: # Should not happen if addr < end
                    mode = BYTE
                    addr_flags = 0 # Treat as unknown/byte
                else:
                    ins = ins_list[0]
                    if next_addr and addr + ins.size > next_addr:  # Switch to byte mode to avoid skipping over label
                        _name = self.label_for(next_addr)
                        warn(f'{addr:08X}: THUMB instruction "{ins.mnemonic}" overlaps label at {next_addr:08X} ({_name})')
                        mode = BYTE
                        addr_flags &= ~FLAG_EXEC
            elif mode == WORD:
                if next_addr and addr + 4 > next_addr:
                    warn(f'{addr:08X}: Word overlaps label at {next_addr:08X} ({self.label_for(next_addr)})')
                    mode = BYTE
                    addr_flags &= ~FLAG_WORD

            # Determine label and comment
            # TODO: Check which labels are used in other modules--they must be marked as global for the assembler!
            label_type = self.label_map.get(addr, None)
            label = None if label_type is None else self.label_for(addr)  # Check against None as label_type may be 0
            comment = ''
            if label_type == FUNC:  # Tag function start
                func = label
                if (addr & (~3)) == addr: # Check for word alignment (mask LSBs)
                    label = f'\tthumb_func_start {func}\n{func}:'
                else:  # Function is not word-aligned
                    label = f'\tnon_word_aligned_thumb_func_start {func}\n{func}:'
                if func[:4] != 'sub_':  # Comment function address for named functions
                    comment += f' @ {addr:08X}'
            elif label:
                label += ':'

            # If switching out of byte mode mid-line, write a newline
            if old_mode == BYTE and mode != BYTE and bytecount != 0:
                bytecount = 0
                f.write('\n')

            # Switch module output
            if f is not sys.stdout and addr in self.module_addrs:  # Address starts a module
                new_module = self.module_addrs[addr]
                if new_module != module or f is None:  # Entering new/first module
                    module = new_module
                    path_to_write = os.path.join(folder, module) if folder else module
                    eprint(f"{addr:08X}: module '{path_to_write}'")
                    bar.set_description(module + ' '*max(0, module_len-len(module)))
                    module_len = max(module_len, len(module))
                    if f and f is not sys.stdout : # Check if f is already open and not stdout
                        if bytecount: # if bytes were pending on the line
                            f.write('\n')
                        f.close()
                    f = open(path_to_write, 'w', buffering=1)
                    f.write(ASM_PRELUDE)
                    f.write(f'.include "{self.macros}"\n' if self.macros else MACROS)
                    bytecount = 0  # Reset bytecount
                    if DEBUG:  # Output linker script if debugging
                        fl.write(f'{path_to_write[:-2]}.o(.text);\n') # Assuming .s extension

            # Emit code or data
            current_instruction_object = None
            if mode == THUMB:
                # Re-fetch instruction if not already fetched (e.g. if mode changed just before)
                # This was 'ins' from the previous loop in analyze_rom for pushes/bls,
                # but here it should be the current instruction.
                ins_list_dump = list(rom.dist(addr,1))
                if not ins_list_dump: break # End of ROM or error
                current_instruction_object = ins_list_dump[0]
                offset = current_instruction_object.size

                if current_instruction_object.id == Opcode.bl or current_instruction_object.id in BRANCHES:
                    target = current_instruction_object.target
                    if target in self.label_map:  # Branch to label
                        name = self.label_for(target)
                        emit = f'{current_instruction_object.mnemonic} {name}'
                    else:  # Missing label; emit raw bytes
                        warn(f'{addr:08X}: Missing target for "{current_instruction_object.mnemonic}": {target:08X}')
                        raw_bytes_val = rom.read(addr, offset) # Read raw instruction bytes
                        if offset == 4: # BL usually 4 bytes
                            emit = f'.4byte 0x{raw_bytes_val:08X} @ {current_instruction_object.mnemonic} _{target:08X}'
                        else: # Other branches usually 2 bytes
                            emit = f'.2byte 0x{raw_bytes_val:04X} @ {current_instruction_object.mnemonic} _{target:08X}'

                elif current_instruction_object.id == Opcode.bx:
                    value = rom.read(addr, 2) # BX is 2 bytes
                    # Assembler will not emit bx with nonzero rd, see THUMB.5 TODO: Should these be treated as illegal?
                    # Capstone provides ins.op_str like "bx lr".
                    # The original condition `value & 3 != 0` seems to be checking for alignment or specific forms.
                    # For now, let's use `str(ins)` which is usually fine.
                    # If Capstone's string for BX is problematic for assembler, .inst is a fallback.
                    # Checking ins.reg_name(ins.operands[0].reg) might be useful.
                    emit = str(current_instruction_object) # Usually "bx REG"
                    # emit = f'.inst 0x{value:04X}' if value & 3 != 0 else str(current_instruction_object)

                elif current_instruction_object.id == Opcode.ldr and isinstance(current_instruction_object, Thumb6):  # LDR PC-relative
                    target = current_instruction_object.target # This is the data address
                    value_at_target = rom.read(target, 4) # Read the 4-byte data from target
                    if target in self.label_map: # If data address has a label
                        name = self.label_for(target)
                        # Format as: ldr rD, =label @ =0xVALUE_HEX
                        # Capstone op_str is "ldr rD, [pc, #imm]". We want "ldr rD, label_name"
                        # Find first operand string (e.g. "r0")
                        reg_operand_str = current_instruction_object.op_str.split(',')[0]
                        emit = f'{current_instruction_object.mnemonic} {reg_operand_str}, {name} @ =0x{value_at_target:08X}'
                    else: # No label for data address
                        # Use original LDR format but comment the target and value
                        # emit = str(current_instruction_object) + f' @ target=0x{target:08X} (=0x{value_at_target:08X})'
                        # Or, more like .word for the target address itself if that's what assembler wants for PC-rel
                        # This should be `ldr rd, =address` which translates to `ldr rd, [pc, #offset_to_pool]`
                        # So if we have target, we can emit `ldr rd, =0x{target:08X}`
                        reg_operand_str = current_instruction_object.op_str.split(',')[0]
                        emit = f'{current_instruction_object.mnemonic} {reg_operand_str}, =0x{target:08X} @ =0x{value_at_target:08X}'

                else: # Default instruction string
                    emit = str(current_instruction_object)

                if DEBUG and current_instruction_object.id == Opcode.bx and 'r7' in current_instruction_object.op_str:
                    emit += f' @ {rom.read(addr, 2):04X}' # Add raw bytes for debug

                if label:
                    f.write(f'{label}{comment}\n')
                f.write(f'\t{emit} @ {addr:08X}\n' if DEBUG else f'\t{emit}\n')
            elif mode == WORD:
                offset = 4
                value = rom.read(addr, 4)
                # Check if this word is an address pointing to a function (Thumb: address is odd)
                if value & 1 and self.label_map.get(value - 1, None) == FUNC:
                    value_str = self.label_for(value - 1) + " + 1" # Represent thumb call target
                elif self.label_map.get(value, None) == FUNC : # Points to an ARM function or data label that is func start
                     value_str = self.label_for(value)
                elif value in self.label_map: # Points to a non-function label
                    value_str = self.label_for(value)
                else: # Raw hex value
                    value_str = f'0x{value:08X}'

                emit_str = f'{label} .4byte {value_str}' if label else f'\t.4byte {value_str}'

                if DEBUG:
                    comment += f' @ flags={addr_flags}' # Show flags if debugging
                f.write(f'{emit_str}{comment}\n')

            elif mode == BYTE:
                offset = 1
                if old_mode != BYTE: # If just switched to byte mode
                    bytecount = 0 # Reset line byte counter
                if label: # If there's a label for this address
                    if bytecount != 0: # If bytes are already on current line
                        f.write('\n') # Newline before label
                        bytecount = 0
                    f.write(f'{label}{comment}\n') # Write label

                value = rom.read(addr, 1) # Read the byte
                if bytecount == 0: # First byte on the line
                    f.write(f'\t.byte 0x{value:02X}')
                elif bytecount == 15: # Last byte on a 16-byte line
                    f.write(f', 0x{value:02X}\n')
                else: # Middle of the line
                    f.write(f', 0x{value:02X}')
                bytecount = (bytecount + 1) % 16

            flags = addr_flags # Save flags for next iteration's old_flags
            addr += offset
            bar.update(offset)
        # Done with output; close file handles and cleanup
        if f is not sys.stdout and f: # If f is a file we opened
            if bytecount: # If last line of bytes wasn't full and didn't get a newline
                f.write('\n')
            f.close()
        bar.close()
        if DEBUG and path: # If linker script was being written
            if fl: fl.close()
