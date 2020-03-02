from os.path import join as joinp

from PyInstaller.__main__ import run

from luvdis import __version__


args = ['-y', '--clean', '-F',
        '--add-data', joinp('luvdis', 'functions.inc') + ';luvdis',
        '--add-data', joinp('luvdis', 'gba-db.pickle') + ';luvdis',
        '-n', f'Luvdis-{__version__}', joinp('luvdis', '__main__.py')]


run(args)
