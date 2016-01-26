// namespace.

module sandbox.namespace;

import core.sys.posix.unistd;
import core.sys.posix.stdlib;
import core.sys.posix.sys.resource;
import core.sys.posix.sys.stat;
import core.stdc.errno;
import core.exception : RangeError;

import std.string;
import std.conv : to;
import std.range : repeat;
import std.array : array;
import std.exception : errnoEnforce;

import std.stdio;

import sandbox.process;
import sandbox.profile;


immutable
{
  int PR_SET_DUMPABLE = 4;
  int PR_SET_CHILD_SUBREAPER = 36;

  ulong MS_NOSUID = 2;
  ulong MS_NODEV = 4;
  ulong MS_NOEXEC = 8;
  ulong MS_NOATIME = 1024;

  int CLONE_NEWNS = 0x0002_0000;
  int CLONE_NEWUTS = 0x0400_0000;
  int CLONE_NEWIPC = 0x0800_0000;
  int CLONE_NEWUSER = 0x1000_0000;
  int CLONE_NEWPID = 0x2000_0000;
  int CLONE_NEWNET = 0x4000_0000;

  uint _LINUX_CAPABILITY_VERSION_3 = 0x20080522;
  uint _LINUX_CAPABILITY_U32S_3 = 2;
}


extern (C)
{
  int prctl(int, ulong, ulong, ulong, ulong);
  int mount(const char*, const char*, const char*, ulong, const void*);
  int chroot(const char*);
  int unshare(int);
  int capset(cap_user_header_t, const_cap_user_data_t);

  struct __user_cap_header_struct {
    uint ver;
    int pid;
  };

  struct __user_cap_data_struct {
    uint effective;
    uint permitted;
    uint inheritable;
  };

  alias cap_user_header_t = const __user_cap_header_struct*;
  alias const_cap_user_data_t = const __user_cap_data_struct*;
}


void activate()
{
  auto chrootJail = new ChrootJail;
  chrootJail.enter;
}


class ChrootJail
{
  const char* dirname;

  this()
  {
    string tmpDirname = "/tmp/sandbox.XXXXXX";
    dirname = cast(const) mkdtemp(cast(char*)tmpDirname.toStringz);
    if (dirname is null) {
      errnoEnforce(false, "Cound not create temporary directory.");
    }

    errnoEnforce(mount("tempfs".toStringz,
                       dirname,
                       "tempfs".toStringz,
                       MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID,
                       null) == 0);
  }

  // Enter the `chroot` jail.
  void enter()
  {
    errnoEnforce(chroot(dirname) == 0);
    errnoEnforce(chdir(".") == 0);
  }
}

// Removes fake-superuser capabilities. This removes our ability to mess with the filesystem view
// we've set up.
auto dropCapabilities()
{
  auto capabilitiyData = repeat(__user_cap_data_struct(0, 0, 0), _LINUX_CAPABILITY_U32S_3).array;
  const user_cap_header = __user_cap_header_struct(_LINUX_CAPABILITY_VERSION_3, 0);
  auto result = capset(&user_cap_header, capabilitiyData.ptr);
  assert(result == 0);
  return result;
}


// Sets up the user and PID namespaces.
void prepareNamespace(in pid_t uid, in pid_t gid)
in {
  assert(unshare(CLONE_NEWUSER | CLONE_NEWPID) == 0);
}
body {
  import std.stdio : File;

  // See http://crbug.com/457362 for more information on this.
  File("/proc/self/setgroups", "w").write("deny");

  File("/proc/self/gid_map", "w").writef("0 %d 1", gid);
  File("/proc/self/uid_map", "w").writef("0 %d 1", uid);
}


// spawn a child process in a new namespace.
pid_t spawnJail(
  Profile profile,
  in char[][] args,
  in string[string] env = null)
{
  // Store our root namespace UID and GID because they're going to change once we enter a user
  // namespace.
  pid_t
    uid = getuid(),
    gid = getgid();

  // Always create an IPC namespace, a mount namespace, and a UTS namespace.
  auto flags = cast() CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS;

  //  Additionally, if we aren't allowing network operations, create a network namespace.
  if (profile.allowedOperation.canFind(Operation.NetworkOutbound)) {
    flags |= CLONE_NEWNET;
  }

  int[2] fds;
  // Create a pipe so we can communicate the PID of our grandchild back.
  errnoEnforce(pipe(fds) == 0);

  // Set this `prctl` flag so that we can wait on our grandchild.
  errnoEnforce(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);

  if (fork() == 0) {
    pid_t pid;

    close(fds[0]);

    prepareNamespace(uid, gid);

    if ((pid = fork()) == 0) {
      // Enter the auxiliary namespaces.
      errnoEnforce(unshare(flags) == 0);

      // run command.
      sandbox.process.exec(args);
      abort();
      assert(false);
    }

    long ret = core.sys.posix.unistd.write(fds[1], cast(const void*)&pid, pid_t.sizeof);
    assert(ret == pid_t.sizeof);
    exit(0);
  }

   // Grandparent execution continues here. First, close the writing end of the pipe.
  close(fds[1]);
  pid_t grandchildPid = 0;

  // Retrieve our grandchild's PID.
  assert(core.sys.posix.unistd.read(fds[0], cast(void*)&grandchildPid, pid_t.sizeof) == pid_t.sizeof);

  return grandchildPid;
}


// ditto.
pid_t spawnJail(Profile profile, in string[] args)
{
  return spawnJail(profile, cast(const char[][])args);
}
