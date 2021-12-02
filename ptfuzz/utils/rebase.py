from pwn import *
'''
 REBASE the target binary to defeat
 ASLR in order to calculate 
 function and block offsets.
'''


def rebase(pid):
    """ 
    Rebase the target binary by reading
    proc/maps and finding the base address.
    """
    maps = open(f'/proc/{pid}/maps').read()
    base = maps.split('-')[0]
    return int(base, 16)
