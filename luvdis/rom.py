""" GBA ROM class & tools. """
import sys
import pickle
import pkg_resources
import xml.etree.ElementTree as ET
from hashlib import sha1, md5
from io import BytesIO

from luvdis.common import eprint, warn
from luvdis.disasm import disasm


DB_F = pkg_resources.resource_stream('luvdis', 'gba-db.pickle')
ROM_DB = None  # Actual ROM db object


class ROMInfo:
    """ GBA ROM information.

    Attributes:
        name (str): ROM title/name.
        size (int): ROM size in bytes.
        md5 (bytes): This ROM's md5 hash.
        sha1 (bytes): This ROM's sha1 hash.
        serial (str): This ROM's serial/game code.
        status (str): ROM/dump status. 'verified' means a dump is good.
    """
    __slots__ = ('name', 'size', 'md5', 'sha1', 'serial', 'status')

    def __init__(self, name, size, md5, sha1, serial, status):
        self.name, self.size, self.md5, self.sha1, self.serial, self.status = name, size, md5, sha1, serial, status

    def __str__(self):
        return f'{self.name} #{self.serial} ({self.status})'


class ROM:
    """ GBA ROM representation.

    See https://problemkaputt.de/gbatek.htm#gbacartridgeheader

    Attributes:
        size (int): Size of the ROM in bytes.

    Args:
        path (str): Path to ROM.
        detect (bool): Whether to attempt & display ROM detection. Defaults to `True`.
    """

    def __init__(self, path, detect=True):
        self._info = False
        with open(path, 'rb') as f:
            self.buffer = f.read()
            self.size = len(self.buffer)
            self.f = BytesIO(self.buffer)
        if detect:
            info = self.info
            if info:
                status = '✔' if info.status == 'verified' else f'({info.status})'
                eprint(f"ROM detected: '{info.name}' {status}")
                if info.status != 'verified':  # Bad dump
                    digest = ''.join('%02X' % b for b in info.sha1)
                    warn(f'Unverified/bad dump! sha1: {digest}')
            else:
                eprint(f"ROM unknown: '{self.title}' {self.game_code}-{self.maker_code}")

    @property
    def title(self):
        """ Title/name of this ROM. """
        b = self.readb(0x0A0, 12)
        index = b.find(0)
        if index != -1:
            b = b[:index]
        return b.decode('ascii')

    @property
    def game_code(self):
        """ Game code of this ROM. """
        b = self.readb(0x0AC, 4)
        return b.decode('ascii')

    @property
    def maker_code(self):
        """ Maker code of this ROM. """
        b = self.readb(0x0B0, 2)
        return b.decode('ascii')

    @property
    def info(self):
        """ ROM info, if available. Otherwise `None`. """
        global ROM_DB, DB_F
        if self._info is not False:  # Cache info value
            return self._info
        if ROM_DB is None:
            ROM_DB = pickle.load(DB_F)
        by_serial, by_md5, by_sha1 = ROM_DB
        h = sha1()
        h.update(self.buffer)
        digest = h.digest()
        info0 = by_sha1.get(digest, None)
        h = md5()
        h.update(self.buffer)
        digest = h.digest()
        info1 = by_md5.get(digest, None)
        self._info = info0 if info0 is info1 else None
        return self._info

    def read(self, addr, size=1, safe=True):
        """ Read a little-endian integer of any size at an address.

        Args:
            addr (int): Address to read.
            size (int): Size of integer in bytes.
            safe (bool): Maintain original cursor position. Defaults to `True`.
        """
        if safe:
            cursor = self.f.tell()
        self.f.seek(addr & 0xffffff)
        b = self.f.read(size)
        if safe:
            self.f.seek(cursor)
        return int.from_bytes(b, 'little', signed=False)

    def readb(self, addr, n):  # Read n bytes at address
        addr &= 0xffffff
        return self.buffer[addr:addr+n]

    def dist(self, addr=0x08000000, count=None):  # Disassemble ROM
        self.f.seek(addr & 0xffffff)
        if count is None:
            yield from disasm(self.f, addr)
        else:
            yield from disasm(self.f, addr, count)


def make_rom_db(path):  # Build db from XML
    tree = ET.parse(path)
    by_serial = {}
    by_md5 = {}
    by_sha1 = {}  # Serial -> ROMInfo
    for game in tree.findall('game'):
        for rom in game.findall('rom'):
            name, size, md5, sha1, serial, status = (rom.get(attr) for attr in ('name', 'size', 'md5', 'sha1', 'serial', 'status'))
            if name[-4:] == '.gba':
                name = name[:-4]
            print(name)
            size = int(size)
            if serial is None:  # Skip games without serial numbers
                continue
            serial = serial.upper()
            md5 = bytes.fromhex(md5)
            sha1 = bytes.fromhex(sha1)
            obj = ROMInfo(name, size, md5, sha1, serial, status)
            by_serial[serial] = by_md5[md5] = by_sha1[sha1] = obj
    db = (by_serial, by_md5, by_sha1)
    with open('gba-db.pickle', 'wb') as f:
        pickle.dump(db, f)


def main():
    make_rom_db(sys.argv[1])


if __name__ == '__main__':
    main()
