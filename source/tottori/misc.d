// Sandboxing on Linux via miscellaneous kernel features.

module tottori.misc;

import core.sys.posix.sys.stat : umask, mode_t;
import core.sys.posix.sys.resource : setrlimit, rlimit;
import core.sys.posix.unistd : setsid;
import std.exception : errnoEnforce;

import tottori.seccomp : prctl;


extern(C)
{
    int clearenv();
}


const int RLIMIT_FSIZE = 1;
const int PR_SET_DUMPABLE = 4;


void activate()
{
    rlimit limit = { 0, 0 };
    errnoEnforce(setrlimit(RLIMIT_FSIZE, &limit) == 0);

    // Set a restrictive `umask` so that even if files happened to get written it'd be hard to do
    // anything with them.
    umask(0);

    // Disable core dumps and debugging via `PTRACE_ATTACH`.
    errnoEnforce(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);

    // Enter a new session group.
    errnoEnforce(setsid() != -1);

    // Clear out the process environment.
    assert(clearenv() == 0);
}
