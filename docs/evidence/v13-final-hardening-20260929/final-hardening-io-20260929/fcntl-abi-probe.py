import ctypes,os,tempfile,platform,json
lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True)
lib.fcntl.restype=ctypes.c_int
results=[]
with tempfile.TemporaryFile() as f:
 for variant,argtypes in [('incorrect-fixed-three',[ctypes.c_int,ctypes.c_int,ctypes.c_int]),('correct-variadic-two',[ctypes.c_int,ctypes.c_int])]:
  lib.fcntl.argtypes=argtypes
  ctypes.set_errno(0)
  fd=lib.fcntl(f.fileno(),67,ctypes.c_int(300))
  results.append({'signature':variant,'requested_minimum_fd':300,'result_fd':fd,'errno':ctypes.get_errno()})
  if fd>=0:os.close(fd)
print(json.dumps({'architecture':platform.machine(),'F_DUPFD_CLOEXEC':67,'results':results,'reference':'https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms'},indent=2))
