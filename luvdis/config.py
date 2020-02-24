""" Tools for reading/writing function configuration. """
import re


# [arm_func|thumb_func] <address> [module] [name]
cfg_re = re.compile(r'(thumb_func|arm_func)?\s*(?:0x)?([0-9a-fA-F]{7,8})(?:\s+(\S+\.s))?(?:\s+(\S+)\r?\n)?')


def read_config(path):
    """ Reads a configuration file into an address map.

    Args:
        path (str): Path to function configuration file.

    Returns:
        dict: Mapping from function address to (name, module) tuples.
    """
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
    """ Writes an address map to a configuration file.

    Args:
        addr_map (dict): Mapping from function address to (name, module) tuples.
        path (str): Path to write.
    """
    with open(path, 'w', buffering=1) as f:
        f.write(f'# {len(addr_map)} functions\n# [arm_func|thumb_func] <address> [module] [name]\n')
        for addr in sorted(addr_map):
            name, module = addr_map[addr]
            parts = [f'0x{addr:07X}']
            if module:
                parts.append(module)
            if name:
                parts.append(name)
            f.write(' '.join(parts) + '\n')
