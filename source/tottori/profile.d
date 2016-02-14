module tottori.profile;

enum Operation
{
  FileReadAll,
  FileReadMetadata,
  NetworkOutbound,
  SystemInfoRead,
}

final class Profile
{
  Operation[] allowedOperation;
  string[] mountPaths;

  this(Operation[] _allowedOperation, string[] _mountPaths = null)
  {
    allowedOperation = _allowedOperation;
    mountPaths = _mountPaths;
  }
}
