module sandbox.sandbox;

import sandbox.profile;
import sandbox.seccomp;
import sandbox.namespace;
import sandbox.misc;

import core.sys.posix.unistd;

class Sandbox
{
  Profile profile;

  this(Profile _profile)
  {
    profile = _profile;
  }

  pid_t run(in char[][] args)
  {
    return spawnJail(profile, args);
  }
}

class ChildSandbox
{
  Profile profile;

  this(Profile _profile)
  {
    profile = _profile;
  }

  auto activate()
  {
    sandbox.namespace.activate();
    sandbox.misc.activate();
    auto filter = new Filter(profile);
    filter.activate();
  }

  auto run(in char[][] args)
  {
    spawnJail(profile, args);
  }
}
