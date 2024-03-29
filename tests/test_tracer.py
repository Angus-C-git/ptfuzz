from tracer import health_check, ptrace_exec
from ptfuzz.bindings import ptrace_requests
import pytest
from pwn import process, logging

# ::::::::::::::::::::::::: CONFIG :::::::::::::::::::::::::

# disable logging from pwntools
logging.disable()


def start_tracee():
    """ start a test program 'tracee' 
        and extract its pid 
    """
    tracee = process('./targets/tracee')
    pid = tracee.pid
    return pid


'''
Define tests for the tracer module. This tests
the underlying C functions and helpers that the
ptfuzz module relies on for its bindings. 



TODO :: some tests are shakey since we do not
wait for the ptrace calls (such as attach) to
complete. Causing some tests to fail occasionally (often).
'''

# ::::::::::::::::::::::::: TESTS :::::::::::::::::::::::::


def test_import_tracer():
    """ test tracer import works
        as a prerequisite
    """
    assert health_check() == 1


def test_ptrace_attach():
    """ test tracer attach works """
    pid = start_tracee()
    assert pid != 0
    result = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid
    )
    assert result == 0


def test_ptrace_detach():
    """ test tracer detach works """
    pid = start_tracee()
    assert pid != 0

    # attach to the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid,
        0
    )
    assert result == 0

    signal = 0
    result = ptrace_exec(
        ptrace_requests.PTRACE_DETACH,
        pid
    )
    assert result == 0


def test_ptrace_cont():
    """ test tracer cont works """
    pid = start_tracee()
    assert pid != 0

    # attach to the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid
    )
    assert result == 0

    # continue the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_CONT,
        pid
    )
    assert result == 0

    # dont detach -> process has/will exit


def test_ptrace_syscall():
    """ test tracer syscall works """
    pid = start_tracee()
    assert pid != 0

    # attach to the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid
    )

    # call PTRACE_SYSCALL
    result = ptrace_exec(
        ptrace_requests.PTRACE_SYSCALL,
        pid
    )
    assert result == 0

    # detach from the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_DETACH,
        pid
    )
    assert result == 0


def test_ptrace_single_step():
    """ test tracer single step works """
    pid = start_tracee()
    assert pid != 0

    # attach to the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_ATTACH,
        pid
    )
    assert result == 0

    # single step the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_SINGLESTEP,
        pid
    )

    assert result == 0

    # detach from the process
    result = ptrace_exec(
        ptrace_requests.PTRACE_DETACH,
        pid
    )
    assert result == 0

    # TODO :: remaining ptrace calls

    def test_ptrace_read_data():
        """ test tracer read data works """
        pid = start_tracee()
        assert pid != 0

        # attach to the process
        result = ptrace_exec(
            ptrace_requests.PTRACE_ATTACH,
            pid
        )
        assert result == 0

        # read the data
        result = ptrace_exec(
            ptrace_requests.PTRACE_PEEKDATA,
            pid
        )
        assert result == 0

        # detach from the process
        result = ptrace_exec(
            ptrace_requests.PTRACE_DETACH,
            pid
        )
        assert result == 0
