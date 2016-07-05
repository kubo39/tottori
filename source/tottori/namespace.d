// namespace.

module tottori.namespace;

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
import std.file : mkdirRecurse, isDir, isFile;
import std.path : dirName;
import std.algorithm : canFind;

import std.stdio;

import tottori.process;
import tottori.profile;
import tottori.utils;


immutable
{
    int PR_SET_DUMPABLE = 4;
    int PR_SET_CHILD_SUBREAPER = 36;

    ulong MS_NOSUID = 2;
    ulong MS_NODEV = 4;
    ulong MS_NOEXEC = 8;
    ulong MS_NOATIME = 1024;
    ulong MS_BIND = 4096;
    ulong MS_REC = 16384;
    ulong MS_MGC_VAL = 0xc0ed_0000;

    int CLONE_NEWNS = 0x0002_0000;
    int CLONE_NEWUTS = 0x0400_0000;
    int CLONE_NEWIPC = 0x0800_0000;
    int CLONE_NEWUSER = 0x1000_0000;
    int CLONE_NEWPID = 0x2000_0000;
    int CLONE_NEWNET = 0x4000_0000;

    uint _LINUX_CAPABILITY_VERSION_3 = 0x20080522;
    uint _LINUX_CAPABILITY_U32S_3 = 2;

    int O_CLOEXEC = 0x80000;
}


extern (C)
{
    int prctl(int, ulong, ulong, ulong, ulong);
    int mount(const char*, const char*, const char*, ulong, const void*);
    int chroot(const char*);
    int unshare(int);
    int capset(cap_user_header_t, const_cap_user_data_t);
    int pipe2(ref int[2], int);

    struct __user_cap_header_struct
    {
        uint ver;
        int pid;
    };

    struct __user_cap_data_struct
    {
        uint effective;
        uint permitted;
        uint inheritable;
    };

    alias cap_user_header_t = const __user_cap_header_struct*;
    alias const_cap_user_data_t = const __user_cap_data_struct*;
}


// Enter the `chroot` jail.
void activate(Profile profile)
{
    char* tmpDirname = cast(char*) "/tmp/tottori.XXXXXX\0".toStringz;
    const char* dirname = cast(const) mkdtemp(tmpDirname);

    if (dirname is null)
    {
        errnoEnforce(false, "Cound not create temporary directory.");
    }

    errnoEnforce(mount(cast(const char*) "tmpfs\0".toStringz,
                       dirname,
                       cast(const char*) "tmpfs\0".toStringz,
                       MS_NOATIME | MS_NODEV | MS_NOEXEC | MS_NOSUID,
                       null) == 0);

    if (profile.allowedOperation.canFind(Operation.FileReadAll) ||
        profile.allowedOperation.canFind(Operation.FileReadMetadata))
    {
        if (profile.mountPaths !is null)
        {
            foreach (mountPath; profile.mountPaths)
            {
                bindMount(mountPath, dirname);
            }
        }
    }

    errnoEnforce(chroot(dirname) == 0);
    errnoEnforce(chdir(".") == 0);
}


// Bind mounts a path into our chroot jail.
void bindMount(string mountPath, const char* tempDir)
{
    auto destinationPath = tempDir.to!string ~ mountPath;

    if (mountPath.isDir)
    {
        mkdirRecurse(destinationPath);
    }
    else if (mountPath.isFile)
    {
        mkdirRecurse(destinationPath.dirName);
        auto f = File(destinationPath, "w");
        f.close;
    }

    errnoEnforce(mount(mountPath.toStringz,
                       destinationPath.toStringz,
                       "bind".toStringz,
                       MS_MGC_VAL | MS_BIND | MS_REC, null) == 0);
}



// Removes fake-superuser capabilities. This removes our ability to mess with the filesystem view
// we've set up.
auto dropCapabilities()
{
    auto capabilitiyData = repeat(__user_cap_data_struct(0, 0, 0),
                                  _LINUX_CAPABILITY_U32S_3).array;
    const user_cap_header = __user_cap_header_struct(_LINUX_CAPABILITY_VERSION_3, 0);
    auto result = capset(&user_cap_header, capabilitiyData.ptr);
    assert(result == 0);
    return result;
}


// Sets up the user and PID namespaces.
void prepareNamespace(in pid_t uid, in pid_t gid)
{
    errnoEnforce(unshare(CLONE_NEWUSER | CLONE_NEWPID) == 0,
                 "Could not create new user and PID namespaces.");

    import std.stdio : File;

    if (isSupportsDenySetgroups())
    {
        // See http://crbug.com/457362 for more information on this.
        File("/proc/self/setgroups", "w").write("deny");
    }

    File("/proc/self/gid_map", "w").writef("0 %d 1", gid);
    File("/proc/self/uid_map", "w").writef("0 %d 1", uid);
}


// spawn a child process in a new namespace.
Pid spawnChildInNewNamespace(in char[][] args,  const Profile profile)
{
    // Store our root namespace UID and GID because they're going to change once we enter a user
    // namespace.
    pid_t
        uid = getuid(),
        gid = getgid();

    // Always create an IPC namespace, a mount namespace, and a UTS namespace.
    auto flags = cast() CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWUTS;

    //  Additionally, if we aren't allowing network operations, create a network namespace.
    if (profile.allowedOperation.canFind(Operation.NetworkOutbound))
    {
        flags |= CLONE_NEWNET;
    }

    int[2] fds;
    // Create a pipe so we can communicate the PID of our grandchild back.
    errnoEnforce(pipe2(fds, O_CLOEXEC) == 0);

    // Set this `prctl` flag so that we can wait on our grandchild.
    errnoEnforce(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);

    pid_t pid = fork();

    if (pid == -1)
    {
        foreach (fd; fds)
        {
            close(fd);
        }
        errnoEnforce(false, "fork(2) failed.");
    }

    // child process.
    void forkChild()
    {
        static import core.sys.posix.stdio;
        close(fds[0]);

        prepareNamespace(uid, gid);

        pid = fork();

        if (pid == -1)
        {
            close(fds[1]);
            errnoEnforce(false, "fork(2) failed.");
        }

        // grandchild.
        if (pid == 0)
        {
            // Enter the auxiliary namespaces.
            errnoEnforce(unshare(flags) == 0);

            import core.sys.posix.poll : pollfd, poll, POLLNVAL;
            import core.sys.posix.sys.resource : rlimit, getrlimit, RLIMIT_NOFILE;

            // Get the maximum number of file descriptors that could be open.
            rlimit r;
            if (getrlimit(RLIMIT_NOFILE, &r) != 0)
            {
                core.sys.posix.stdio.perror("getrlimit");
                core.sys.posix.unistd._exit(1);
                assert(false);
            }
            immutable maxDescriptors = cast(int)r.rlim_cur;

            // The above, less stdin, stdout, and stderr
            immutable maxToClose = maxDescriptors - 3;

            // Call poll() to see which ones are actually open:
            // Done as an internal function because MacOS won't allow
            // alloca and exceptions to mix.
            @nogc nothrow
            static bool pollClose(int maxToClose)
            {
                import core.stdc.stdlib : alloca;

                pollfd* pfds = cast(pollfd*)alloca(pollfd.sizeof * maxToClose);
                foreach (i; 0 .. maxToClose)
                {
                    pfds[i].fd = i + 3;
                    pfds[i].events = 0;
                    pfds[i].revents = 0;
                }
                if (poll(pfds, maxToClose, 0) >= 0)
                {
                    foreach (i; 0 .. maxToClose)
                    {
                        // POLLNVAL will be set if the file descriptor is invalid.
                        if (!(pfds[i].revents & POLLNVAL)) close(pfds[i].fd);
                    }
                    return true;
                }
                else
                {
                    return false;
                }
            }

            if (!pollClose(maxToClose))
            {
                // Fall back to closing everything.
                foreach (i; 3 .. maxDescriptors) close(i);
            }

            // run command.
            tottori.process.exec(args);
            abort();
            assert(false);
        }

        long ret = core.sys.posix.unistd.write(fds[1], cast(const void*)&pid,
                                               pid_t.sizeof);
        assert(ret == pid_t.sizeof);
        exit(0);
    }

    if (pid == 0)
    {
        forkChild();
        assert(false);
    }

    // Grandparent execution continues here. First, close the writing end of the pipe.
    close(fds[1]);
    pid_t grandchildPid = 0;

    // Retrieve our grandchild's PID.
    assert(core.sys.posix.unistd.read(fds[0],
                                      cast(void*) &grandchildPid,
                                      pid_t.sizeof) == pid_t.sizeof);

    return new Pid(grandchildPid);
}


// ditto.
Pid spawnChildInNewNamespace(in string[] args, const Profile profile)
{
    return spawnChildInNewNamespace(cast(const char[][])args, profile);
}
