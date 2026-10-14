from pathlib import Path
import hashlib,json,os,subprocess,datetime
REPO=Path("/Users/michael/Developer/GPT-Codex/Kalyna")
OUT=Path(__file__).resolve().parent
ROOT=REPO/"work/v13-evidence/rev12-gui-final-20261004/build-20261004T082228Z"
HELPER=REPO/"work/v13-evidence/rev12-gui-final-20261004/run-development.py"
H=ROOT/"artifacts/bin/KeepVaultMac.Tests/release_osx-arm64"
def pins(): return {p.relative_to(H).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(H.rglob("*")) if p.is_file() and not p.is_symlink() and not p.name.startswith(".test-")}
before=json.loads((OUT/"harness-inputs-before.json").read_text());assert pins()==before
assert hashlib.sha256(HELPER.read_bytes()).hexdigest()=="86c3d5e66f6858c9a59e428e79779f4a441bcf55b87660670956d3583f4820a4"
TC=REPO/"work/v13-evidence/rev11-release-b41144e/resume-harness"
for folder,manifest in [("sdk","sdk-copy.json"),("packages","packages-copy.json")]:
 for name,row in json.loads((TC/manifest).read_text()).items():
  p=TC/folder/name
  if row["type"]=="file": assert p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==row["sha256"],name
  elif row["type"]=="symlink": assert p.is_symlink() and os.readlink(p)==row["target"],name
start={"startedUtc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"sourceHead":subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO).decode().strip(),"launcherPid":os.getpid(),"harnessBuild":"082228","harnessInputCount":len(before),"scope":"Fresh complete managed functional regression on current unchanged sources with retained signed Build15 natives. Not a final Build16/AOT/installed GUI release gate."}
env=os.environ.copy();env["KEEPVAULT_TEST_BUILD_ROOT"]=str(ROOT)
cmd=["/usr/bin/python3",str(HELPER),"test","--full","--parallel","1","--dump-key-sheets",str(OUT/"public-key-sheets")]
with (OUT/"launcher.log").open("xb") as log:
 child=subprocess.Popen(cmd,cwd=REPO,env=env,stdout=log,stderr=subprocess.STDOUT);start["helperPid"]=child.pid;(OUT/"start.json").write_text(json.dumps(start,indent=2)+"\n");print("full_helper_pid="+str(child.pid),flush=True);result=child.wait()
after=pins();(OUT/"harness-inputs-after.json").write_text(json.dumps(after,indent=2)+"\n")
(OUT/"exit.json").write_text(json.dumps({"completedUtc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"actualHelperExit":result,"harnessInputsStable":before==after,"status":"PASS" if result==0 and before==after else "FAIL","scope":start["scope"]},indent=2)+"\n")
raise SystemExit(result if result else (0 if before==after else 2))
