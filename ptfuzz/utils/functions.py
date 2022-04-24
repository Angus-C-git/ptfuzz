from pwn import ELF, logging
from struct import pack, unpack

''' 
Resolve function names and addresses 
from a given binary.
'''

# kill pwntools logs
logging.disable()

# don't map these functions as
# they are of no coverage value
default_functions = [
    '__libc_csu_init',
    '__libc_csu_fini',
    '_fini',
    '__do_global_dtors_aux',
    '_start',
    '_init',
    'sub_1034',
    'main'          # test ignoring main
]


def get_functions(binary, base):
    """ 
    Resolve function names and addresses 
    from a given binary.
    """
    proc_elf = ELF(binary)
    proc_elf.address = base

    # extract function names and addresses
    func_map = {}
    for name, function in proc_elf.functions.items():
        if name in default_functions:
            continue
        func_map[name] = function.address
    return func_map
