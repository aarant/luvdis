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
    print(f'STR {m.group(1)}')
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



if __name__ == '__main__':
    s = 'Something seems to\nhave gone wrong.^Who are you?\rAnd how did you get\nhere?\rTASing? What is that?'
    s = 'The teleporter must\nhave been overloaded.\rThis poor trainer\nisn\'t well.\r' + \
        'With all that\ninterference..\rit\'s as if someone\npressed every button^all at once!\rBut that means..'
    s = 'It must have picked up\na different signal..\rfrom another region?\n..Or another world?\r' + \
        'So where did it send\nBill?'
    s = 'Leaf, we have to run\nthe experiment again.\rI think I can reverse\nit, and put things^back to normal.\r' + \
        '..I hope.\rJust step inside the\ndoor when it starts.'
    s = 'Oh no..\rJust hang on! I can\nturn it off!'

    s = 'Hey!\rDid you enjoy the TAS?\rThis took quite a long\ntime to make..\rDo you want to have a\nreal battle?'
    s = 'OK! Come back anytime!'
    s = "\xfcさあ6Alright, here goes.."
    s = "RIP Poochyena.."
    s = "Marshtomp used\nRNG hacks!"
    s = "It hurt itself in its\nconfusion!"
    s = "No u"
    h = '0000000000000000CEBBCDFF0000000000000202E1D9E6E6E4FF0000F19A0000E900990040420F0000FF000090007600A600620119191919FF000000FF0000000000000000FFE4E1FFFFFF3F00000000'
    s = 'This it! TAS!'
    s = '\xfcさ6あPlayer defeated\nTASVideos merrp!\r'
    s = 'Thanks for watching!\nIf you want a challenge..\rtry beating this without\nhacks sometime!'
    s = '\rAnd finally..\nthe TAS is over!\rThanks to everyone who\nhelped in its making!\rWe hope to see you\nagain!'
    s = 'This is it! TAS!'
    convert_binary(s)
