module sandbox.sandbox;

import sandbox.profile;
import sandbox.seccomp;
import sandbox.namespace;
import sandbox.misc;

import core.sys.posix.unistd;


pid_t runSandbox(in char[][] args, const Profile profile)
{
  return spawnChildInNewNamespace(args, profile);
}


auto activateNamespaceAndMisc(Profile profile)
{
  sandbox.namespace.activate(profile);
  sandbox.misc.activate();
  auto filter = new Filter(profile);
  filter.activate();
}
