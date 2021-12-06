from pwn import u32, u64, u16, u8, unhex
from struct import pack, unpack
''' 
Various type conversion helpers.
'''


def bytes2word(_bytes, size=8):
    """
    Convert a bytes string to an unsigned integer (a CPU word).
    """
    # if size == 8:
    #     return u32(_bytes)

    # return u32(_bytes)
    # hex_str = ''.join('{:02x}'.format(x) for x in _bytes)
    # print(unhex(hex_str))
    # print(f"bytes2word u64: {hex(u64(_bytes))}")
    # print(f"hex ? {hex_str}")

    # # stripped = _bytes[2:]
    # # print(f"bytes2word stripped: {hex(stripped)}")
    # # print(f"bytes2word " {unhex(u64(_bytes))})

    # return unpack("L", _bytes)[0]
    return u32(_bytes)
