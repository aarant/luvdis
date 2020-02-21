import subprocess
import os
import sys

from os.path import join as joinp

from luvdis.charmap import convert_file

AS = joinp('asm', 'arm-none-eabi-as')
LD = joinp('asm', 'arm-none-eabi-ld')
LINK_TEMPLATE = joinp('asm', 'linker.ld')


def sremove(path):  # Silently remove file
    try:
        os.remove(path)
    except OSError:
        pass


def fill_link(template, addr, path, out_path):
    with open(template, 'r') as f:
        content = f.read()
    content = content.replace('%ADDR%', f'0x{addr:08x}')
    content = content.replace('%PATH%', path)
    with open(out_path, 'w') as f:
        f.write(content)


def assemble(path, addr=0, clean=True, debug=True):
    """ Assemble and link THUMB assembly code at an address.

    Args:
        path (str): Path to assemble.
        addr (int): Address to link at. If zero no linking is done.
        clean (bool): Whether to clean intermediate files. Defaults to True.
        debug (bool): Whether to export the binary as hex. Defaults to True.
    """
    root, ext = os.path.splitext(os.path.basename(path))
    asm_path = joinp('build', f'{root}.s')
    obj_path = joinp('build', f'{root}.o')
    link_path = joinp('build', f'{root}.ld')
    elf_path = joinp('build', f'{root}.elf')
    bin_path = joinp('build', f'{root}.bin')
    hex_path = joinp('build', f'{root}.hex')
    work_paths = asm_path, obj_path, link_path, elf_path
    print(f'AS  {root}')
    convert_file(path, asm_path)
    subprocess.run([AS, '-mcpu=arm7tdmi', '-o', obj_path, asm_path], check=True)  # Assemble
    if addr:  # Link
        print(f'LD  {root} at 0x{addr:08x}')
        fill_link(LINK_TEMPLATE, addr, obj_path, link_path)
        subprocess.run([LD, '-T', link_path, '-o', elf_path, obj_path], check=True)  # Link
    else:  # Just extract
        elf_path = obj_path
    subprocess.run(['arm-none-eabi-objcopy', '-O', 'binary', '-j', '.text', elf_path, bin_path], check=True)
    if debug:
        with open(bin_path, 'rb') as f_in, open(hex_path, 'w') as f_out:
            f_out.write(f_in.read().hex())
    if clean:
        for to_clean in work_paths:
            sremove(to_clean)
    size = os.path.getsize(bin_path)
    print(f'BIN {root} ({size} bytes)')


if __name__ == '__main__':
    args = sys.argv[1:]
    addr = int(args[1], base=16) if len(args) > 1 else 0
    assemble(args[0], addr)
