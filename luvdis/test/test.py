import unittest
import os.path
import glob
from os.path import join as joinp

from luvdis.assemble import assemble
from luvdis.decoder import Opcode, disasm

BASE_ADDRESS = 0x08000000


def write_asm(gen, path, labels):
    with open(path, 'w', buffering=1) as f:
        f.write('.syntax unified\n.text\n.thumb\n')
        for ins in gen:
            if ins.address in labels:
                f.write(f'{labels[ins.address]}:\n')
            if hasattr(ins, 'target') and ins.target in labels:
                f.write(f'\t{ins.mnemonic} {labels[ins.target]} @ {ins.address:07X}\n')
            else:
                f.write(f'\t{ins} @ {ins.address:07X}\n')


def compare_binaries(p1, p2):
    with open(p1, 'rb') as f1, open(p2, 'rb') as f2:
        b1 = f1.read()
        b2 = f2.read()
        addr = BASE_ADDRESS
        for i, j in zip(b1, b2):
            if i != j:
                raise Exception(f'Address {addr:08X} differs ({addr-BASE_ADDRESS} bytes in)')
            addr += 1
        return len(b1) == len(b2)


def round_trip(path, labels=None):
    labels = {} if labels is None else labels
    root, ext = os.path.splitext(os.path.basename(path))
    assemble(path, BASE_ADDRESS, debug=False)
    build_clean = joinp('build', f'{root}.bin')
    with open(build_clean, 'rb') as f:
        dis = disasm(f, BASE_ADDRESS)
        asm_rt = joinp('test', f'{root}_rt.s')
        write_asm(dis, asm_rt, labels)
    assemble(asm_rt, BASE_ADDRESS, debug=False)
    build_rt = joinp('build', f'{root}_rt.bin')
    try:
        eq = compare_binaries(build_clean, build_rt)
    except:
        raise
    else:
        paths = glob.glob(joinp('build', f'{root}*')) + [asm_rt]
        for path in paths:
            try:
                os.remove(path)
            except:
                pass
    return eq


class DecoderTest(unittest.TestCase):
    def test_full(self):
        self.assertTrue(round_trip(joinp('test', 'test_full.s'), {0x08000088: 'label', 0x08000092: 'label2'}))


if __name__ == '__main__':
    unittest.main()
