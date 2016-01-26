import std.stdio;
import std.algorithm : canFind;
import core.stdc.stdlib : exit;

import sandbox.process : spawn, wait;
import sandbox.sandbox : Sandbox, ChildSandbox;
import sandbox.profile : Profile, Operation;


// sandbox profile.
Profile profile()
{
  return new Profile([ Operation.FileReadAll,
                       Operation.FileReadMetadata,
                       Operation.NetworkOutbound,
                       Operation.SystemInfoRead ]);
}


void main(string[] args)
{
  if (args.canFind("child")) {  // child.
    auto sandbox = new ChildSandbox(profile());
    sandbox.activate();
    "Not printed!".writeln;
  }
  else {  // parent.
    auto sandbox = new Sandbox(profile());
    auto pid = sandbox.run(args ~ "child");
    exit(wait(pid));
  }
}
