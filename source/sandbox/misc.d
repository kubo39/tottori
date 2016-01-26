module sandbox.misc;

import core.sys.posix.sys.stat : umask, mode_t;
import core.sys.posix.sys.resource : setrlimit, rlimit;
import core.sys.posix.unistd : setsid;

import sandbox.seccomp : prctl;


extern(C)
{
  int clearenv();
}


const int RLIMIT_FSIZE = 1;
const int PR_SET_DUMPABLE = 4;


auto activate()
{
  rlimit limit = { 0, 0 };
  int result = setrlimit(RLIMIT_FSIZE, &limit);
  if (result != 0) {
    return result;
  }

  // Set a restrictive `umask` so that even if files happened to get written it'd be hard to do
  // anything with them.
  umask(0);

  // Disable core dumps and debugging via `PTRACE_ATTACH`.
  assert(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);

  // Enter a new session group.
  setsid();

  // Clear out the process environment.
  return clearenv();
}
