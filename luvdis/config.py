""" Tools for reading/writing function configuration. """
import re
import sys


# [arm_func|thumb_func] <address> [module] [name]
cfg_re = re.compile(r'(thumb_func|arm_func)?\s*(?:0x)?([0-9a-fA-F]{7,8})(?:\s+(\S+\.s))?(?:\s+(\S+)\r?\n)?')


def read_config(path):  # TODO: Detect and flag duplicate names
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


def strip_unknown(config):  # Strip unknown names from config
    unk_re = re.compile(r'sub_[0-9a-fA-F]{7,8}')
    new_config = {}
    for k, (name, module) in config.items():
        if name and unk_re.match(name):
            name = None
        new_config[k] = (name, module)
    return new_config


def write_config(addr_map, path):
    """ Writes an address map to a configuration file.

    Args:
        addr_map (dict): Mapping from function address to (name, module) tuples.
        path (str): Path to write.
    """
    named = unnamed = 0
    current_module = None
    modules = set()
    names = set()
    with open(path, 'w', buffering=1) as f:
        nfuncs = str(len(addr_map))
        s0 = f'# {nfuncs} functions, '
        s1 = '{} named, {} unnamed'
        f.write(s0+' '*len(s1.format(nfuncs, nfuncs)) + '\n')
        f.write('# [arm_func|thumb_func] <address> [module] [name]\n')
        for addr in sorted(addr_map):
            name, module = addr_map[addr]
            parts = [f'0x{addr:07X}']
            if module:
                parts.append(module)
                if module != current_module:
                    if current_module:
                        modules.add(current_module)
                    if module in modules:
                        print(f"Warning: {addr:08X}: Module '{module}' was already seen!", file=sys.stderr)
                    f.write(f'# {module}\n')
                    current_module = module
            if name:
                if name in names:
                    print(f"Warning: {addr:08X}: Duplicate name '{name}'", file=sys.stderr)
                    name = None
                else:
                    names.add(name)
                parts.append(name)
                named += 1
            else:
                unnamed += 1
            f.write(' '.join(parts) + '\n')
        f.seek(len(s0))
        f.write(s1.format(named, unnamed))
