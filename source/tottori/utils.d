module tottori.utils;

import std.file : exists;


string kProcSelfSetgroups = "/proc/self/setgroups";

bool isSupportsDenySetgroups()
{
    return exists(kProcSelfSetgroups);
}
