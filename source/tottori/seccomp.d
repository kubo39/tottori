// `seccomp-bpf` support on recent Linux kernels.

module tottori.seccomp;

import std.algorithm : canFind;
import std.conv : to;
import std.string : toStringz;

import core.sys.posix.fcntl : O_RDONLY, O_NONBLOCK;
import core.sys.posix.sys.socket : AF_UNIX, AF_INET, AF_INET6;
import core.sys.posix.unistd : write, close;

import std.exception : errnoEnforce;

import tottori.profile;

pragma(lib, "seccomp");


extern (C)
{
  struct sock_filter
  {
    ushort code;
    uint k;
    ubyte jt;
    ubyte jf;
  }

  struct sock_fprog {
    short len;
    const sock_filter* filter;
  }

  int prctl(int, ulong, ulong, ulong, ulong);
  int mkstemp(char*);
}

immutable
{
  uint EM_X86_64 = 62;

  // A flag set in the architecture number for all 64-bit architectures.
  uint __AUDIT_ARCH_64BIT = 0x8000_0000;
  // A flag set in the architecture number for all little-endian architectures.
  uint __AUDIT_ARCH_LE = 0x4000_0000;

  // The architecture number for x86-64.
  uint AUDIT_ARCH_X86_64 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE;

  uint SECCOMP_RET_KILL = 0;
  uint SECCOMP_RET_ALLOW = 0x7fff_0000;

  ushort LD = 0x00;
  ushort JMP = 0x05;
  ushort RET = 0x06;

  ushort W = 0;
  ushort ABS = 0x20;

  ushort JEQ = 0x10;
  ushort JSET = 0x40;

  ushort K = 0x00;

  uint SYSCALL_NR_OFFSET = 0;
  uint ARCH_NR_OFFSET = 4;
  uint ARG_0_OFFSET = 16;
  uint ARG_1_OFFSET = 24;
  uint ARG_2_OFFSET = 32;

  int AF_NETLINK = 16;

  int O_NOCTTY = 256;
  int O_CLOEXEC = 524288;

  int FIONREAD = 0x541b;
  int FIOCLEX = 0x5451;

  int NETLINK_ROUTE = 0;

  uint MADV_NORMAL = 0;
  uint MADV_RANDOM = 1;
  uint MADV_SEQUENTIAL = 2;
  uint MADV_WILLNEED = 3;
  uint MADV_DONTNEED = 4;

  int PR_SET_SECCOMP = 22;
  int PR_SET_NO_NEW_PRIVS = 38;

  ulong SECCOMP_MODE_FILTER = 2;
}


// syscall.
const
{
  uint NR_read = 0;
  uint NR_write = 1;
  uint NR_open = 2;
  uint NR_close = 3;
  uint NR_stat = 4;
  uint NR_fstat = 5;
  uint NR_poll = 7;
  uint NR_lseek = 8;
  uint NR_mmap = 9;
  uint NR_mprotect = 10;
  uint NR_munmap = 11;
  uint NR_brk = 12;
  uint NR_rt_sigprocmask = 14;
  uint NR_rt_sigreturn = 15;
  uint NR_ioctl = 16;
  uint NR_access = 21;
  uint NR_madvise = 28;
  uint NR_socket = 41;
  uint NR_connect = 42;
  uint NR_sendto = 44;
  uint NR_recvfrom = 45;
  uint NR_recvmsg = 47;
  uint NR_bind = 49;
  uint NR_getsockname = 51;
  uint NR_clone = 56;
  uint NR_exit = 60;
  uint NR_readlink = 89;
  uint NR_getuid = 102;
  uint NR_sigaltstack = 131;
  uint NR_futex = 202;
  uint NR_sched_getaffinity = 204;
  uint NR_exit_group = 231;
  uint NR_set_robust_list = 273;
  uint NR_sendmmsg = 307;
  uint NR_getrandom = 318;
}

/// Syscalls that are always allowed.
static const ALLOWED_SYSCALLS = [
  NR_brk,
  NR_close,
  NR_exit,
  NR_exit_group,
  NR_futex,
  NR_getrandom,
  NR_getuid,
  NR_mmap,
  NR_mprotect,
  NR_munmap,
  NR_poll,
  NR_read,
  NR_recvfrom,
  NR_recvmsg,
  NR_rt_sigprocmask,
  NR_rt_sigreturn,
  NR_sched_getaffinity,
  NR_sendmmsg,
  NR_sendto,
  NR_set_robust_list,
  NR_sigaltstack,
  NR_write,
  ];

static ALLOWED_SYSCALLS_FOR_FILE_READ = [
  NR_access,
  NR_fstat,
  NR_lseek,
  NR_readlink,
  NR_stat,
  ];

static ALLOWED_SYSCALLS_FOR_NETWORK_OUTBOUND = [
  NR_bind,
  NR_connect,
  NR_getsockname,
  ];

const
{
  sock_filter ALLOW_SYSCALL = sock_filter(
  RET + K,
  SECCOMP_RET_ALLOW,
  0,
  0,
  );

 sock_filter VALIDATE_ARCHITECTURE_0 = sock_filter(
  LD + W + ABS,
  ARCH_NR_OFFSET,
  0,
  0,
  );

 sock_filter VALIDATE_ARCHITECTURE_1 = sock_filter(
  JMP + JEQ + K,
  AUDIT_ARCH_X86_64,
  1,
  0,
  );

 sock_filter KILL_PROCESS = sock_filter(
  RET + K,
  SECCOMP_RET_KILL,
  0,
  0,
  );

 sock_filter EXAMINE_SYSCALL = sock_filter(
   LD + W + ABS,
   SYSCALL_NR_OFFSET,
   0,
   0,
  );

 sock_filter EXAMINE_ARG_0 = sock_filter(
  LD + W + ABS,
  ARG_0_OFFSET,
  0,
  0,
  );

 sock_filter EXAMINE_ARG_1 = sock_filter(
  LD + W + ABS,
  ARG_1_OFFSET,
  0,
  0,
  );

 sock_filter EXAMINE_ARG_2 = sock_filter(
  LD + W + ABS,
  ARG_2_OFFSET,
  0,
  0,
  );
}

alias VALIDATE_ARCHITECTURE_2 = KILL_PROCESS;

static sock_filter[] FILTER_PROLOGUE = [
  VALIDATE_ARCHITECTURE_0,
  VALIDATE_ARCHITECTURE_1,
  VALIDATE_ARCHITECTURE_2,
  ];

static sock_filter[] FILTER_EPILOGUE = [
  KILL_PROCESS,
  ];


static dumpfile = "/tmp/seccomp.XXXXXX\0";


// seccomp-bpf filter.
class Filter
{
  sock_filter[] program;

  this(Profile profile)
  {
    program = FILTER_PROLOGUE;

    // allow syscall in default.
    allowSyscalls(ALLOWED_SYSCALLS);

    if (profile.allowedOperation.canFind(Operation.FileReadAll) ||
        profile.allowedOperation.canFind(Operation.FileReadMetadata)) {
      allowSyscalls(ALLOWED_SYSCALLS_FOR_FILE_READ);

      // only allow file reading.
      ifSyscallIs(NR_open, {
          ifArg1HasntSet(~(O_RDONLY |  O_CLOEXEC | O_NOCTTY | O_NONBLOCK),
                         { allowThisSyscall(); });
        });

      // Only allow the `FIONREAD` or `FIOCLEX` `ioctl`s to be performed.
      ifSyscallIs(NR_ioctl, {
          ifArg1Is(FIONREAD, { allowThisSyscall(); });
          ifArg1Is(FIOCLEX, { allowThisSyscall(); });
        });
    }

    if (profile.allowedOperation.canFind(Operation.NetworkOutbound)) {
      allowSyscalls(ALLOWED_SYSCALLS_FOR_NETWORK_OUTBOUND);

      // Only allow Unix, IPv4, IPv6, and netlink route sockets to be created.
      ifSyscallIs(NR_socket, {
          ifArg0Is(AF_UNIX, { allowThisSyscall(); });
          ifArg0Is(AF_INET, { allowThisSyscall(); });
          ifArg0Is(AF_INET6, { allowThisSyscall(); });
          ifArg0Is(AF_NETLINK, {
              ifArg2Is(NETLINK_ROUTE, { allowThisSyscall(); });
            });
        });
    }

    program ~= FILTER_EPILOGUE;
  }

  void dump()
  {
    char* path = cast(char*) dumpfile.toStringz;
    int fd = mkstemp(path);
    errnoEnforce(fd != -1, "mkstemp(3) failed.");
    auto nbytes = program.length + sock_filter.sizeof;
    assert(.write(fd, cast(void*) program.ptr, nbytes) == nbytes);
    scope(exit) .close(fd);
  }

  void allowThisSyscall()
  {
    program ~= ALLOW_SYSCALL;
  }

  void allowSyscalls(const uint[] syscalls)
  {
    foreach (number; syscalls) {
      ifSyscallIs(number, () { allowThisSyscall();});
    }
  }

  void ifSyscallIs(const uint number, void delegate() then)
  {
    program ~= EXAMINE_SYSCALL;
    ifKIs(number, then);
  }

  void ifArg0Is(const uint number, void delegate() then)
  {
    program ~= EXAMINE_ARG_0;
    ifKIs(number, then);
  }

  void ifArg1Is(const uint number, void delegate() then)
  {
    program ~= EXAMINE_ARG_1;
    ifKIs(number, then);
  }

  void ifArg1HasntSet(const uint value, void delegate() then)
  {
    program ~= EXAMINE_ARG_1;
    ifKHasntSet(value, then);
  }

  void ifArg2Is(const uint value, void delegate() then)
  {
    program ~= EXAMINE_ARG_2;
    ifKIs(value, then);
  }

  void ifKIs(const uint value, void delegate() then)
  {
    auto index = program.length;
    program ~= sock_filter(
      JMP + JEQ + K,
      value,
      0,
      0);
    then();
    program[index].jf = (program.length - index - 1).to!ubyte;
  }

  void ifKHasntSet(const uint value, void delegate() then)
  {
    auto index = program.length;
    program ~= sock_filter(
      JMP + JSET + K,
      value,
      0,
      0,
      );
    then();
    program[index].jt = (program.length - index - 1).to!ubyte;
  }

  /// Activates this filter, applying all of its restrictions forevermore. This can only be done
  /// once
  void activate()
  {
    errnoEnforce(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    const sock_fprog fprog = sock_fprog(program.length.to!short, program.ptr);
    errnoEnforce(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                       cast(ulong)&fprog) == 0, "Not supported seccomp.");
  }
}
