from rich import print
import pytest
from pwn import process

# helpers
from os import execl, fork, waitpid, WIFSTOPPED, WSTOPSIG
from signal import Signals, SIGTRAP, SIGSTOP

# :::::::::::::::::: config ::::::::::::::::::
from tracer import ptrace_exec
from ptfuzz.bindings import ptrace_requests
from ptfuzz.coverage.BreakpointMap import BreakpointMap
from rich.console import Console
TEST_BIN_PATH = 'targets/tracee'
TEST_BIN_PATH_2 = 'targets/simple'
IO_BIN = 'targets/natt'


def test_get_breakpoints():
    """
    Test that we can get the breakpoints
    for a process
    """
    proc = process(TEST_BIN_PATH)
    pid = proc.pid

    bp_map = BreakpointMap(pid, TEST_BIN_PATH)
    # print(f"[>>] function map")
    # print(bp_map.func_map)

    assert len(bp_map.func_map) == 6
    proc.close()

    # run test on secondary binary
    proc = process(IO_BIN)
    pid = proc.pid
    bp_map = BreakpointMap(pid, IO_BIN)
    assert len(bp_map.func_map) == 5


def test_set_breakpoints():
    """
    Test that we can set breakpoints
    and trap on them
    """
    BREAKPOINT_TARGET = 6  # 6 functions in the target
    bp_count = 0

    proc = process(TEST_BIN_PATH)
    pid = proc.pid

    # attach to process
    res = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid,
        0
    )
    assert res == 0

    bp_map = BreakpointMap(pid, TEST_BIN_PATH)
    # plant breakpoints
    bp_map.set_breakpoints()

    # check that we halted
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        stopCode = WSTOPSIG(status[1])
        print(f"[>>] Attach halted the process {stopCode}")

        # signal should be SIGSTOP on attach
        assert stopCode == SIGSTOP

        # continue the process
        res = ptrace_exec(
            ptrace_requests.PTRACE_CONT,
            pid
        )
        assert res == 0

    else:
        print(f"[>>] Something horrible occurred, {status[1]}")

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    print(f"[>>] wait got => {status}")
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(f"[>>] Hit breakpoint!")
            bp_count += 1

            # continue the process
            res = ptrace_exec(
                ptrace_requests.PTRACE_CONT,
                pid
            )
            assert res == 0
        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    # tmp assert
    assert bp_count == BREAKPOINT_TARGET - 5
    # next breakpoint 2/6

    # TODO :: after we hit a breakpoint the instruction pointer should be
    # 		  at the breakpoint location, however this instruction
    # 		  is no longer the same as the original instruction / valid
    # 		  and will therefore cause a segfault. To fix this we need to
    # 		  reset the breakpoint to the original instruction and rollback
    # 		  the instruction pointer one step.
    #
    # 		  This requires modifying the breakpoint map to store the original
    # 		  instruction.
    proc.close()


def test_set_breakpoints_2():
    """
    Test that we can set breakpoints
    and trap on them
    """
    bp_count = 0

    proc = process(TEST_BIN_PATH_2)
    pid = proc.pid

    print(f"[>>] started second process")
    # attach to process
    res = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid,
    )
    assert res == 0

    bp_map = BreakpointMap(pid, TEST_BIN_PATH_2)
    # plant breakpoints
    bp_map.set_breakpoints()

    # check that we halted
    status = waitpid(pid, 0)
    print(f"[>>] wait got => {status}")
    if (WIFSTOPPED(status[1])):
        stopCode = WSTOPSIG(status[1])
        print(f"[>>] Attach halted the process {stopCode}")

        # signal should be SIGSTOP on attach
        assert stopCode == 19

        # continue the process
        res = ptrace_exec(
            ptrace_requests.PTRACE_CONT,
            pid
        )
        assert res == 0

    else:
        print(f"[>>] Something horrible occurred, {status[1]}")

    # push IO forward
    proc.sendline("21")

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    print(f"[>>] wait got => {status}")
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(f"[>>] Hit breakpoint!")
            bp_count += 1

            # continue the process
            res = ptrace_exec(
                ptrace_requests.PTRACE_CONT,
                pid
            )
            assert res == 0
        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")
