from ptrace_requests import *


def ptrace(request, pid, addr=0, data=0):
    """
    ptrace wrapper
    """
    result = ptrace_exec(request, pid, addr, data)


def attach(pid):
    """
    attach to a process
    """
    ptrace(PTRACE_ATTACH, pid)


def detach(pid):
    """
    detach from a process
    """
    ptrace(PTRACE_DETACH, pid)


def cont(pid):
    """
    continue a process
    """
    ptrace(PTRACE_CONT, pid)


def watch_syscall(pid):
    """
    trace syscalls in target process
    """
    ptrace(PTRACE_SYSCALL, pid)


def get_regs(pid):
    """
    get registers from target process
    """
    regs = ptrace(PTRACE_GETREGS, pid)
    print(regs)
    return regs


def set_regs(pid, regs):
    """
    set registers in target process
    """
    ptrace(PTRACE_SETREGS, pid, 0, regs)


# quick test
if __name__ == "__main__":
    print("[>>] ptrace bindings dev tests")
    # attach(getpid())
