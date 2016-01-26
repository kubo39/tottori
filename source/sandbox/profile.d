module sandbox.profile;

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

  this(Operation[] _allowedOperation)
  {
    allowedOperation = _allowedOperation;
  }
}
