import std.stdio;
import std.algorithm : canFind;
import core.stdc.stdlib : exit;

import sandbox.process : spawn, wait;
import sandbox.sandbox : runSandbox, activateNamespaceAndMisc;
import sandbox.profile : Profile, Operation;


// sandbox profile.
Profile profile()
{
  return new Profile([ Operation.FileReadAll,
                       Operation.FileReadMetadata,
                       Operation.NetworkOutbound,
                       Operation.SystemInfoRead ],
                     ["/lib", "/etc"]);
}


void main(string[] args)
{
  if (args.canFind("child")) {  // grand-child.
    activateNamespaceAndMisc(profile());
    "Not printed!".writeln;
  }
  else {  // parent.
    auto pid = runSandbox(args ~ "child", profile());
    exit(wait(pid));
  }
}
