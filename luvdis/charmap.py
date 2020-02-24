import math
import re

char_to_byte = {'あ': 0x01, 'い': 0x02, 'え': 0x04, '6': 0xA7,
                'A': 0xBB, 'B': 0xBC, 'C': 0xBD, 'D': 0xBE, 'E': 0xBF, 'F': 0xC0, 'G': 0xC1, 'H': 0xC2, 'I': 0xC3,
                'J': 0xC4, 'K': 0xC5, 'L': 0xC6, 'M': 0xC7, 'N': 0xC8, 'O': 0xC9, 'P': 0xCA, 'Q': 0xCB, 'R': 0xCC,
                'S': 0xCD, 'T': 0xCE, 'U': 0xCF, 'V': 0xD0, 'W': 0xD1, 'X': 0xD2, 'Y': 0xD3, 'Z': 0xD4, 'a': 0xD5,
                'b': 0xD6, 'c': 0xD7, 'd': 0xD8, 'e': 0xD9, 'f': 0xDA, 'g': 0xDB, 'h': 0xDC, 'i': 0xDD, 'j': 0xDE,
                'k': 0xDF, 'l': 0xE0, 'm': 0xE1, 'n': 0xE2, 'o': 0xE3, 'p': 0xE4, 'q': 0xE5, 'r': 0xE6, 's': 0xE7,
                't': 0xE8, 'u': 0xE9, 'v': 0xEA, 'w': 0xEB, 'x': 0xEC, 'y': 0xED, 'z': 0xEE, '\r': 0xFB, '\n': 0xFE,
                '.': 0xB8, '?': 0xAC, ' ': 0x00, '!': 0xAB, '^': 0xFA, ',': 0xB4, '\'': 0xB3, chr(0xfc): 0xFC,
                'さ': 0x0B}

string_re = re.compile(r'\.string\s+([\'"].*[\'"])')


def convert_match(m):
    s = eval(m.group(1))
    return convert(s)


def convert(s: str):
    b = [char_to_byte[c] for c in s] + [0xff]
    lines = []
    for i in range(math.ceil(len(b)/16)):
        row = b[16*i:16*(i+1)]
        line = '.byte ' + ', '.join(f'0x{x:02X}' for x in row)
        lines.append(line)
    return '\n'.join(lines)


def convert_file(path, out_path):
    with open(path, 'r') as f_in, open(out_path, 'w') as f_out:
        content = f_in.read()
        replaced, _ = string_re.subn(convert_match, content)
        f_out.write(replaced)


def convert_binary(s):
    b = bytes([char_to_byte[c] for c in s] + [0xff])
    with open('input.bin', 'wb') as f:
        f.write(b)


def convert_hex(h):
    with open('input.bin', 'wb') as f:
        f.write(bytearray.fromhex(h))
