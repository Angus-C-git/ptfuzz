'''
    Pythonic data structure to represent
    ptrace registers struct

    NOTE :: only support linux x86_64

    TODO :: support other architectures
           by extracting cpu info from 
           /proc/cpuinfo ?

    @credits: 

        + register fields from
        (python-ptrace)[https://github.com/vstinner/python-ptrace]
'''

from ctypes import (Structure, Union, sizeof,
                    c_char, c_ushort, c_int, c_uint, c_ulong, c_void_p,
                    c_uint16, c_uint32, c_uint64, c_size_t)


# tmp constant, TODO :: move these

# 64bit - standard
ARCH_X86_64 = True

# 32bit
ARCH_X86_32 = False

# arm
ARCH_ARM = False

# ::::::::::::::::: ptrace registers struct :::::::::::::::::


class ptrace_regs(Structure):
    """ ptrace registers struct, pythonic DS"""
    if ARCH_X86_64:
        _fields_ = (
            ("r15", c_ulong),
            ("r14", c_ulong),
            ("r13", c_ulong),
            ("r12", c_ulong),
            ("rbp", c_ulong),
            ("rbx", c_ulong),
            ("r11", c_ulong),
            ("r10", c_ulong),
            ("r9", c_ulong),
            ("r8", c_ulong),
            ("rax", c_ulong),
            ("rcx", c_ulong),
            ("rdx", c_ulong),
            ("rsi", c_ulong),
            ("rdi", c_ulong),
            ("orig_rax", c_ulong),
            ("rip", c_ulong),
            ("cs", c_ulong),
            ("eflags", c_ulong),
            ("rsp", c_ulong),
            ("ss", c_ulong),
            ("fs_base", c_ulong),
            ("gs_base", c_ulong),
            ("ds", c_ulong),
            ("es", c_ulong),
            ("fs", c_ulong),
            ("gs", c_ulong)
        )
    elif ARCH_X86_32:
        _fields_ = (
            ("ebx", c_ulong),
            ("ecx", c_ulong),
            ("edx", c_ulong),
            ("esi", c_ulong),
            ("edi", c_ulong),
            ("ebp", c_ulong),
            ("eax", c_ulong),
            ("ds", c_ushort),
            ("__ds", c_ushort),
            ("es", c_ushort),
            ("__es", c_ushort),
            ("fs", c_ushort),
            ("__fs", c_ushort),
            ("gs", c_ushort),
            ("__gs", c_ushort),
            ("orig_eax", c_ulong),
            ("eip", c_ulong),
            ("cs", c_ushort),
            ("__cs", c_ushort),
            ("eflags", c_ulong),
            ("esp", c_ulong),
            ("ss", c_ushort),
            ("__ss", c_ushort),
        )
    elif ARCH_ARM:
        pass    # TODO :: implement ARM registers
    else:
        pass    # TODO :: implement other architectures


class ptrace_iovec(Structure):
    _fields_ = [
        ('iov_base', c_void_p),
        ('iov_len', c_size_t)
    ]
