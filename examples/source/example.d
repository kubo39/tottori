import std.stdio;
import std.algorithm : canFind;
import core.stdc.stdlib : exit;

import tottori.process : spawn, wait;
import tottori.sandbox : runSandbox, activateNamespaceAndMisc;
import tottori.profile : Profile, Operation;


// tottori profile.
Profile profile()
{
    return new Profile([ Operation.FileReadAll,
                         Operation.FileReadMetadata,
                         Operation.NetworkOutbound,
                         Operation.SystemInfoRead ],
                       ["/lib\0", "/etc\0"]);
}


void main(string[] args)
{
    if (args.canFind("child"))  // grand-child.
    {
        activateNamespaceAndMisc(profile());
        "Not printed!".writeln;
    }
    else   // parent.
    {
        auto pid = runSandbox(args ~ "child", profile());
        exit(wait(pid));
    }
}
