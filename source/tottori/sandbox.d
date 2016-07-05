module tottori.sandbox;

import tottori.profile;
import tottori.seccomp;
import tottori.namespace;
import tottori.misc;
import tottori.process;

import core.sys.posix.unistd;


Pid runSandbox(in char[][] args, Profile profile)
{
    debug
    {
        auto filter = new Filter(profile);
        filter.dump;
    }
    return spawnChildInNewNamespace(args, profile);
}


auto activateNamespaceAndMisc(Profile profile)
{
    tottori.namespace.activate(profile);
    tottori.misc.activate();
    // auto filter = new Filter(profile);
    // filter.activate();
}
