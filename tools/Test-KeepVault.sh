#!/bin/zsh -f
set -euo pipefail
umask 077
PATH='/usr/bin:/bin:/usr/sbin:/sbin'
export PATH
unset ZDOTDIR ENV BASH_ENV CDPATH PERL5OPT PERL5LIB PYTHONHOME PYTHONPATH \
  RUBYOPT RUBYLIB NODE_OPTIONS DEVELOPER_DIR SDKROOT TOOLCHAINS \
  DOTNET_STARTUP_HOOKS DOTNET_ADDITIONAL_DEPS DOTNET_SHARED_STORE DOTNET_ROOT \
  DOTNET_ROOT_X64 DOTNET_ROOT_ARM64 DOTNET_HOST_PATH MSBuildSDKsPath \
  MSBUILD_EXE_PATH NUGET_PACKAGES NUGET_HTTP_CACHE_PATH NUGET_SCRATCH \
  NUGET_PLUGIN_PATHS NUGET_CREDENTIALPROVIDERS_PATH \
  CORECLR_ENABLE_PROFILING CORECLR_PROFILER CORECLR_PROFILER_PATH \
  COR_ENABLE_PROFILING COR_PROFILER COR_PROFILER_PATH

script_dir=${0:A:h}
repo_root=${script_dir:h}
test_project=${repo_root}/KeepVaultMac.Tests/KeepVaultMac.Tests.csproj
private_root=$(/usr/bin/mktemp -d /private/tmp/keep-vault-test-runner.XXXXXXXX)
/bin/chmod 0700 ${private_root}
private_root_identity=$(/usr/bin/stat -f '%d:%i' ${private_root})
cleanup() {
  set +e
  if [[ -d ${private_root:-} && ! -L ${private_root:-} \
      && ${private_root} == /private/tmp/keep-vault-test-runner.* \
      && $(/usr/bin/stat -f '%d:%i' ${private_root} 2>/dev/null || print invalid) == ${private_root_identity:-invalid} ]]; then
    /bin/rm -rf -- ${private_root}
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

dotnet_command=$(${script_dir}/Provision-VerifiedDotnet-macOS.sh \
  --target ${private_root}/dotnet-sdk)
mkdir -m 0700 ${private_root}/home ${private_root}/packages \
  ${private_root}/http-cache ${private_root}/scratch ${private_root}/tmp \
  ${private_root}/artifacts
private_artifacts=${private_root}/artifacts

run_dotnet_clean() {
  /usr/bin/env -i \
    HOME=${private_root}/home \
    PATH=${PATH} \
    TMPDIR=${private_root}/tmp \
    DOTNET_CLI_HOME=${private_root}/home \
    NUGET_PACKAGES=${private_root}/packages \
    NUGET_HTTP_CACHE_PATH=${private_root}/http-cache \
    NUGET_SCRATCH=${private_root}/scratch \
    DOTNET_EnableDiagnostics=0 \
    COMPlus_EnableDiagnostics=0 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1 \
    DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
    DOTNET_ADD_GLOBAL_TOOLS_TO_PATH=false \
    MSBUILDDISABLENODEREUSE=1 \
    KEEPVAULT_TEST_REPOSITORY_ROOT=${repo_root} \
    ${dotnet_command} "$@"
}

for arg in "$@"; do
  if [[ ${arg} == "--no-build" ]]; then
    print -u2 '--no-build is disabled because tests must use a fresh private artifact tree.'
    exit 64
  fi
done

run_dotnet_clean restore ${test_project} --artifacts-path ${private_artifacts} \
  --locked-mode --force --force-evaluate --no-http-cache \
  --disable-build-servers --nologo
run_dotnet_clean build ${test_project} -c Release --no-restore --no-incremental \
  --artifacts-path ${private_artifacts} --disable-build-servers \
  -p:UseSharedCompilation=false --nologo

# Pass all arguments through to runner
run_dotnet_clean run --project ${test_project} -c Release \
  --artifacts-path ${private_artifacts} --no-build --no-restore \
  --disable-build-servers -- "$@"
