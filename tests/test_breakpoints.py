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
import logging
logging.basicConfig(level=logging.DEBUG)

TEST_BIN_PATH = 'targets/tracee'
TEST_BIN_PATH_2 = 'targets/simple'
TEST_BIN_PATH_3 = 'targets/breakpoints'
TEST_BIN_PATH_4 = 'targets/tracee-mod'
IO_BIN = 'targets/natt'


def test_get_breakpoints():
    """
    Test that we can get the breakpoints
    for a process
    """
    proc = process(TEST_BIN_PATH)
    pid = proc.pid

    bp_map = BreakpointMap(pid, TEST_BIN_PATH)
    print(f"\n[{'='*20}] breakpoints [{'='*20}]")
    print(bp_map.breakpoints)

    assert len(bp_map.func_map) == 5
    proc.close()

    # run test on secondary binary
    proc = process(IO_BIN)
    pid = proc.pid
    bp_map = BreakpointMap(pid, IO_BIN)
    assert len(bp_map.func_map) == 4


def test_set_breakpoints():
    """
    Test that we can set breakpoints
    and trap on them
    """
    BREAKPOINT_TARGET = 5  # 5 functions in the target
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
        print(f"\n[>>] Attach halted the process {stopCode}\n")

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

    # ========================> breakpoint [1/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            # re-instantiate the instruction at the halted address and roll back
            # the instruction pointer
            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(
            f"[>>] Something else occurred, {status[1]}, {Signals(status[1]).name}")

    # tmp assert
    assert bp_count == BREAKPOINT_TARGET - 4

    # ========================> breakpoint [2/6] <========================

    # NOTE :: after we hit a breakpoint the instruction pointer should be
    # 		  at the breakpoint location thus we restore the original instruction
    # 		  and then roll back the instruction pointer >> continue

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    print(f"[>>] Wait got {status[1]}")
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            # re-instantiate the instruction at the halted address and roll back
            # the instruction pointer
            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(
            f"[>>] Something else occurred, {status[1]}")

    assert bp_count == BREAKPOINT_TARGET - 3

    # ========================> breakpoint [3/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    # ========================> breakpoint [4/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    # res = ptrace_exec(
    #     ptrace_requests.PTRACE_DETACH,
    #     pid,
    #     0
    # )
    # assert res == 0
    proc.close()


def test_set_breakpoints_2():
    """
    Test that we can set breakpoints
    and trap on them
    """
    bp_count = 0

    proc = process(TEST_BIN_PATH_2)
    pid = proc.pid

    print(f"\n[>>] started second process")
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
    proc.sendline(b"21")

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(f"[>>] Hit breakpoint [1/1]")
            bp_count += 1

            bp_map.update()
        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    proc.close()


def test_set_breakpoints_3():
    """
    Test that we can set breakpoints
    and trap on them
    """
    BREAKPOINT_TARGET = 6  # functions in the target
    bp_count = 0

    proc = process(TEST_BIN_PATH_3)
    pid = proc.pid

    # attach to process
    res = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid,
        0
    )
    assert res == 0

    bp_map = BreakpointMap(pid, TEST_BIN_PATH_3)
    # plant breakpoints
    bp_map.set_breakpoints()

    # check that we halted
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        stopCode = WSTOPSIG(status[1])
        print(f"\n[>>] Attach halted the process {stopCode}\n")

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

    # ========================> breakpoint [1/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            # re-instantiate the instruction at the halted address and roll back
            # the instruction pointer
            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(
            f"[>>] Something else occurred, {status[1]}, {Signals(status[1]).name}")

    # ========================> breakpoint [2/6] <========================

    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        # assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(
            f"[>>] Something else occurred, {status[1]}")

    # ========================> breakpoint [3/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    # ========================> breakpoint [4/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    # ========================> breakpoint [5/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    # ========================> breakpoint [6/6] <========================

    # check that the breakpoints halt the process
    status = waitpid(pid, 0)
    if (WIFSTOPPED(status[1])):
        sigNum = WSTOPSIG(status[1])
        print(f"[>>] stop code: {Signals(sigNum).name} -> {sigNum}")
        assert sigNum == SIGTRAP
        if (sigNum == SIGTRAP):
            print(
                f"[>>] Hit breakpoint >>  [{bp_count + 1}/{BREAKPOINT_TARGET}]")
            bp_count += 1

            bp_map.update()

        else:
            print(
                f"[>>] Something else halted the process {sigNum}, {Signals(sigNum).name}"
            )
    else:
        print(f"[>>] Something else occurred, {status[1]}")

    # kill the process if its still executing
    proc.close()
