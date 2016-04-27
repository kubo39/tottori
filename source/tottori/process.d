module tottori.process;

import std.stdio : writeln;
import std.string : toStringz;
import std.conv : to;

import core.sys.posix.unistd;
import core.sys.posix.sys.wait;


class ProcessException : Exception
{
  this(string msg, string file = __FILE__, size_t line = __LINE__)
  {
    super(msg, file, line);
  }

  // Creates a new ProcessException based on errno.
  static ProcessException newFromErrno(string customMsg = null,
                                       string file = __FILE__,
                                       size_t line = __LINE__)
  {
    import core.stdc.errno;
    import core.stdc.string;

    char[1024] buf;
    auto errnoMsg = to!string(
      core.stdc.string.strerror_r(errno, buf.ptr, buf.length));

    auto msg = !customMsg.length ? errnoMsg
      : customMsg ~ " (" ~ errnoMsg ~ ')';
    return new ProcessException(msg, file, line);
  }
}


version(Linux)
{
  // Made available by the C runtime:
  extern(C) extern __gshared const char** environ;

  unittest
  {
    new Thread({assert(environ !is null);}).start();
  }
}


void exec(in char[][] args)
{
  const name = args[0];

  // Convert program name and arguments to C-style strings.
  auto argz = new const(char)*[args.length+1];
  argz[0] = name.toStringz;
  foreach (i; 1 .. args.length) {
    argz[i] = args[i].toStringz;
  }
  argz[$-1] = null;

  execve(argz[0], argz.ptr, null);
  _exit(1);
  assert(false);
}


auto spawn(in char[][] args)
{
  pid_t pid;

  // child
  if ((pid = fork()) == 0) {
    exec(args);
  }
  // parent
  return pid;
}


// the dirty work for waitpid.
int wait(pid_t pid)
{
  int status;
  for (;;) {
    pid_t check = waitpid(-1, &status, 0);
    if (check == -1) {
      throw new ProcessException("Process does not exist.");
    }
    if (check == pid) {
      break;
    }
  }

  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  else {
    return WTERMSIG(status);
  }
}
