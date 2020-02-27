""" Common functions for printing to stderr, etc. """
import sys


DEBUG = False


def set_debug(debug):
    global DEBUG
    DEBUG = debug


def eprint(*args, **kwargs):  # Print to stderr
    return print(*args, file=sys.stderr, **kwargs)


def warn(s):   # Print a warning
    return eprint('Warning:', s)


def dprint(*args, **kwargs):  # Print to stderr if debugging
    global DEBUG
    if DEBUG:
        return print(*args, file=sys.stderr, **kwargs)
