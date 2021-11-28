/**
 * PTRACE wrapper to expose the ptrace API.
 * 
*/
#include <Python.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <stdio.h>
static PyObject *ptrace_exec(PyObject *self, PyObject *args);
static PyObject *health_check(PyObject *self, PyObject *args);
PyMODINIT_FUNC PyInit_tracer(void);