/**
 * @file ptrace.c
 * @author Angus C
 * 
 * @brief  A ptrace wrapper module to expose 
 * the ptrace API to python.
 * 
 * @version 0.1
 * @date 2021-11-28
 * 
 * @copyright Copyright (c) 2021
 * 
*/
#include "ptrace.h"
#define PY_SSIZE_T_CLEAN
#define UNUSED(arg) arg __attribute__((unused))

PyDoc_STRVAR(
    module_doc,
    "A ptrace C extension for python");

/**
 * @brief wrap the ptrace call with
 * a generalised function that can
 * be used to call any of the ptrace
 * calls using the ptrace costants.
 * 
 */
static PyObject *
ptrace_exec(PyObject *UNUSED(self), PyObject *args)
{
    unsigned long result;
    unsigned int request;
    pid_t pid;
    unsigned long addr = 0;
    unsigned long data = 0;
    void *erno = 0;
    int ret;

    if (!PyArg_ParseTuple(args, "Ii|LLO", &request, &pid, &addr, &data, &erno))
        return NULL;

    ret = ptrace(request, pid, addr, data);

    if (ret == -1)
    {

        if (errno)
        {
            PyErr_Format(
                PyExc_ValueError,
                "ptrace(request=%u, pid=%i, %p, %p) "
                "error #%i: %s",
                request, pid, addr, data,
                errno, strerror(errno));
            return NULL;
        }
    }
    if (result)
        result = ret;

    return PyLong_FromUnsignedLong(result);
}

/**
 * @brief health check function to 
 * call from python to check if the
 * module is working.
 */
static PyObject *
health_check(PyObject *self, PyObject *args)
{
    printf("\n[>>] tracer functions are exposed\n");
    return Py_BuildValue("i", 1);
}

/**
 * @brief define the methods for the
 * ptrace module.
 */
static PyMethodDef tracer_methods[] = {
    {"ptrace_exec", ptrace_exec, METH_VARARGS, "Execute a ptrace call"},
    {"health_check", health_check, METH_VARARGS, "Check if module is alive"},
    {NULL, NULL, 0, NULL}};

/**
 * @brief the module init function
 * 
 */
static struct PyModuleDef tracer_module = {
    PyModuleDef_HEAD_INIT,
    "tracer",
    module_doc,
    0,
    tracer_methods};

/**
 * @brief initialise the tracer 
 * module
 */
PyMODINIT_FUNC
PyInit_tracer(void)
{
    return PyModule_Create(&tracer_module);
}
