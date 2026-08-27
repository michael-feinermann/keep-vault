#!/bin/zsh
set -euo pipefail
umask 077

script_dir=${0:A:h}
repo_root=${script_dir:h}
installer=${script_dir}/Install-KeepVault-macOS.sh
source_app=${repo_root}/build/dev/Keep\ Vault-macOS/Keep\ Vault.app

usage() {
  print -u2 'Usage: Test-Installer-FailureInjection-macOS.sh [--app "Keep Vault.app"]'
  exit 64
}

while (( $# != 0 )); do
  case $1 in
    --app)
      (( $# >= 2 )) || usage
      source_app=$2
      shift 2
      ;;
    *) usage ;;
  esac
done

[[ -x ${installer} && ! -L ${installer} ]] || {
  print -u2 "Transactional installer is unavailable: ${installer}"
  exit 1
}
[[ -d ${source_app} && ! -L ${source_app} ]] || {
  print -u2 "Signed Keep Vault bundle is unavailable: ${source_app}"
  exit 1
}
source_app=${source_app:A}
[[ ${source_app} == ${repo_root}/* ]] || {
  print -u2 'The installer self-test accepts only an app inside this repository.'
  exit 1
}
scanner_source=${source_app:h}/QR-Scanner.app
[[ -d ${scanner_source} && ! -L ${scanner_source} ]] || {
  print -u2 "Signed QR-Scanner companion is unavailable: ${scanner_source}"
  exit 1
}

for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
  [[ -f ${source_app}.launcher${suffix} && ! -L ${source_app}.launcher${suffix} ]] || {
    print -u2 "Keep Vault launcher sidecar is unavailable: ${suffix}"
    exit 1
  }
  [[ -f ${scanner_source}${suffix} && ! -L ${scanner_source}${suffix} ]] || {
    print -u2 "QR-Scanner sidecar is unavailable: ${suffix}"
    exit 1
  }
done

test_tmp_parent=${TMPDIR:-/tmp}
test_tmp_parent=${test_tmp_parent:A}
test_root=$(mktemp -d "${test_tmp_parent}/keep-vault-installer-test.XXXXXXXX")
chmod 0700 ${test_root}
test_root=${test_root:A}
test_root_identity=$(stat -f '%d:%i' ${test_root})
applications_dir=${test_root}/Applications
snapshots_dir=${test_root}/Snapshots
logs_dir=${test_root}/Logs
mkdir -m 0700 ${applications_dir} ${snapshots_dir} ${logs_dir}
print -rn -- keep-vault-installer-test-v1:${EUID}:${test_root_identity} \
  > ${test_root}/.keep-vault-installer-test-root
chmod 0600 ${test_root}/.keep-vault-installer-test-root

cleanup() {
  local current_identity=''
  if [[ -d ${test_root:-} && ! -L ${test_root:-} \
      && ${test_root:h} == ${test_tmp_parent} \
      && ${test_root:t} == keep-vault-installer-test.* ]]; then
    current_identity=$(stat -f '%d:%i' ${test_root} 2>/dev/null || true)
    if [[ ${current_identity} == ${test_root_identity:-invalid} ]]; then
      rm -rf -- ${test_root}
      return
    fi
  fi
  print -u2 "Refusing to clean a replaced installer self-test root: ${test_root:-missing}"
}
trap cleanup EXIT INT TERM

emit_object_state() {
  local object=$1
  local label=$2
  if [[ ! -e ${object} && ! -L ${object} ]]; then
    print -r -- "missing\t${label}"
    return
  fi

  local parent=${object:h}
  local basename=${object:t}
  (
    cd ${parent}
    find -s ${basename} -print
  ) | while IFS= read -r relative; do
    local object_path=${parent}/${relative}
    local mode=$(stat -f '%Lp' ${object_path} 2>/dev/null || print invalid)
    if [[ -L ${object_path} ]]; then
      print -r -- "link\t${mode}\t$(readlink ${object_path})\t${label}/${relative#${basename}}"
    elif [[ -d ${object_path} ]]; then
      print -r -- "dir\t${mode}\t-\t${label}/${relative#${basename}}"
    elif [[ -f ${object_path} ]]; then
      local digest=$(shasum -a 256 ${object_path} | awk '{print $1}')
      print -r -- "file\t${mode}\t${digest}\t${label}/${relative#${basename}}"
    else
      print -r -- "special\t${mode}\t-\t${label}/${relative#${basename}}"
    fi
  done
}

snapshot_private_install() {
  local output=$1
  {
    emit_object_state ${applications_dir}/Keep\ Vault.app 'Keep Vault.app'
    for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      emit_object_state ${applications_dir}/Keep\ Vault.app.launcher${suffix} "Keep Vault.app.launcher${suffix}"
    done
    emit_object_state ${applications_dir}/QR-Scanner.app 'QR-Scanner.app'
    for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      emit_object_state ${applications_dir}/QR-Scanner.app${suffix} "QR-Scanner.app${suffix}"
    done
  } > ${output}
}

snapshot_global_guard() {
  local output=$1
  {
    emit_object_state '/Library/Application Support/Keep Vault/minimum-version' system-anchor
    emit_object_state '/Applications/Keep Vault.app' applications-main
    emit_object_state '/Applications/QR-Scanner.app' applications-scanner
    for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      emit_object_state "/Applications/Keep Vault.app.launcher${suffix}" "applications-launcher${suffix}"
      emit_object_state "/Applications/QR-Scanner.app${suffix}" "applications-scanner${suffix}"
    done
    emit_object_state ${HOME}/Desktop/Keep\ Vault desktop-alias
    for recovery_object in \
      ${HOME}/.Trash/Keep\ Vault\ previous*(N) \
      ${HOME}/.Trash/Keep\ Vault\ leftovers*(N); do
      emit_object_state ${recovery_object} "trash/${recovery_object:t}"
    done
  } > ${output}
}

assert_test_root_not_registered() {
  local phase=$1
  local lsregister=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
  [[ -x ${lsregister} ]] || return 0

  local registration_dump=${snapshots_dir}/launch-services-${phase}.txt
  if ! ${lsregister} -dump > ${registration_dump} 2>/dev/null; then
    print -u2 "Could not inspect LaunchServices after installer self-test phase: ${phase}"
    return 1
  fi
  if grep -Fq -- ${test_root} ${registration_dump}; then
    rm -f -- ${registration_dump}
    print -u2 "The private installer test root was registered with LaunchServices during phase: ${phase}"
    return 1
  fi
  rm -f -- ${registration_dump}
}

verify_private_install() {
  ${script_dir}/Verify-KeepVault-macOS.sh \
    --app ${applications_dir}/Keep\ Vault.app \
    --require-launcher-signature \
    --allow-development >/dev/null 2>&1
  ${script_dir}/Verify-QR-Scanner-macOS.sh \
    --app ${applications_dir}/QR-Scanner.app \
    --allow-development >/dev/null 2>&1
  ${script_dir}/Verify-ReleasePairMetadata-macOS.sh \
    --app ${applications_dir}/Keep\ Vault.app \
    --scanner ${applications_dir}/QR-Scanner.app >/dev/null 2>&1
}

assert_no_transaction_residue() {
  local residue=0
  for candidate in \
    ${applications_dir}/.Keep\ Vault.previous.*.app(N) \
    ${applications_dir}/.Keep\ Vault.failed.*.app(N) \
    ${applications_dir}/.QR-Scanner.previous.*.app(N) \
    ${applications_dir}/.QR-Scanner.failed.*.app(N) \
    ${applications_dir}/.keep-vault-install.*(N/) \
    ${test_root}/install.lock(N) \
    ${test_root}/State/.minimum-version.*(N); do
    print -u2 "Installer transaction residue remained: ${candidate}"
    residue=1
  done
  (( residue == 0 )) || return 1
}

remove_private_recovery() {
  local recovery=${test_root}/Recovery
  [[ ! -e ${recovery} && ! -L ${recovery} ]] && return 0
  if [[ -d ${recovery} && ! -L ${recovery} \
      && $(stat -f '%u' ${recovery}) == ${EUID} ]]; then
    rm -rf -- ${recovery}
  else
    print -u2 'Private recovery directory was replaced; refusing cleanup.'
    return 1
  fi
}

write_private_anchor() {
  local version=$1
  local state=${test_root}/State
  if [[ ! -e ${state} ]]; then
    mkdir -m 0700 -- ${state}
  fi
  [[ -d ${state} && ! -L ${state} && $(stat -f '%u:%Lp' ${state}) == ${EUID}:700 ]] || {
    print -u2 'Private anchor directory is invalid.'
    return 1
  }
  local stage=$(mktemp "${state}/.minimum-version.XXXXXXXX")
  print -rn -- ${version} > ${stage}
  chmod 0600 ${stage}
  mv -f -- ${stage} ${state}/minimum-version
}

remove_private_anchor() {
  local state=${test_root}/State
  if [[ -d ${state} && ! -L ${state} ]]; then
    rm -f -- ${state}/minimum-version
    rmdir ${state}
  elif [[ -e ${state} || -L ${state} ]]; then
    print -u2 'Private anchor directory was replaced; refusing removal.'
    return 1
  fi
}

assert_private_anchor() {
  local expected=$1
  local anchor_file=${test_root}/State/minimum-version
  if [[ ${expected} == absent ]]; then
    [[ ! -e ${anchor_file} && ! -L ${anchor_file} ]] || {
      print -u2 'An anchor-create failure did not restore the absent private anchor state.'
      return 1
    }
    return 0
  fi
  [[ -f ${anchor_file} && ! -L ${anchor_file} \
      && $(stat -f '%u:%Lp:%l' ${anchor_file}) == ${EUID}:600:1 \
      && $(<${anchor_file}) == ${expected} ]] || {
    print -u2 "Private anchor did not return to version ${expected}."
    return 1
  }
}

bound_delete_log=${logs_dir}/bound-delete.log
${script_dir}/Test-InstallerBoundDelete-macOS.sh > ${bound_delete_log} 2>&1
for required_bound_delete_proof in \
  installer_bound_delete_file=true \
  installer_bound_delete_recursive_nofollow=true \
  installer_bound_delete_identity_mismatch_preserved=true \
  installer_bound_delete_directory_guards=true; do
  grep -Fqx ${required_bound_delete_proof} ${bound_delete_log} || {
    print -u2 "Object-bound rollback helper proof is missing: ${required_bound_delete_proof}"
    sed -n '1,160p' ${bound_delete_log} >&2
    exit 1
  }
done
print 'installer_bound_delete_adversarial=pass'

global_before=${snapshots_dir}/global-before.txt
global_after=${snapshots_dir}/global-after.txt
snapshot_global_guard ${global_before}
assert_test_root_not_registered before-baseline

baseline_log=${logs_dir}/baseline.log
${installer} \
  --app ${source_app} \
  --development \
  --applications-dir ${applications_dir} \
  --no-desktop-alias \
  --test-root ${test_root} > ${baseline_log} 2>&1
grep -Fq "installer_test_isolation=${test_root}" ${baseline_log} || {
  print -u2 'The installer did not attest its private test isolation.'
  exit 1
}
verify_private_install
assert_no_transaction_residue
assert_test_root_not_registered after-baseline

candidate_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' ${source_app}/Contents/Info.plist)
[[ ${candidate_version} =~ '^[1-9][0-9]*$' ]] || {
  print -u2 "Self-test requires a positive numeric app build: ${candidate_version}"
  exit 1
}
older_version=$(( candidate_version - 1 ))

failure_points=(
  main-app-replace
  launcher-replace
  scanner-replace
  native-verify
  main-verify
  anchor-create
  anchor-replace
  anchor-post-check
  rollback-anchor
  rollback-app
  recovery-dir-create
  backup-move-main-app
  backup-move-launcher-sha3
  backup-move-launcher-skein
  backup-move-launcher-khsig
  backup-move-launcher-sha3-khsig
  backup-move-launcher-skein-khsig
  backup-move-scanner-app
  backup-move-scanner-sha3
  backup-move-scanner-skein
  backup-move-scanner-khsig
  backup-move-scanner-sha3-khsig
  backup-move-scanner-skein-khsig
  launch-services
  finder-alias
  exit-trap
)

case_index=0
for failure_point in ${failure_points[@]}; do
  (( ++case_index ))
  expected_anchor=${candidate_version}
  case ${failure_point} in
    anchor-create)
      remove_private_anchor
      expected_anchor=absent
      ;;
    anchor-replace|anchor-post-check|rollback-anchor)
      write_private_anchor ${older_version}
      expected_anchor=${older_version}
      ;;
    *)
      write_private_anchor ${candidate_version}
      ;;
  esac

  verify_private_install
  before_snapshot=${snapshots_dir}/${case_index}-${failure_point}-before.txt
  after_snapshot=${snapshots_dir}/${case_index}-${failure_point}-after.txt
  snapshot_private_install ${before_snapshot}

  case_log=${logs_dir}/${case_index}-${failure_point}.log
  set +e
  ${installer} \
    --app ${source_app} \
    --development \
    --applications-dir ${applications_dir} \
    --no-desktop-alias \
    --test-root ${test_root} \
    --inject-failure ${failure_point} > ${case_log} 2>&1
  case_status=$?
  set -e
  if (( case_status != 86 )); then
    print -u2 "Failure point ${failure_point} returned ${case_status}, expected 86."
    sed -n '1,160p' ${case_log} >&2
    exit 1
  fi
  grep -Fq "installer_fault_injected=${failure_point}" ${case_log} || {
    print -u2 "Installer did not reach named failure point: ${failure_point}"
    sed -n '1,160p' ${case_log} >&2
    exit 1
  }

  remove_private_recovery
  assert_no_transaction_residue
  verify_private_install
  snapshot_private_install ${after_snapshot}
  cmp -s ${before_snapshot} ${after_snapshot} || {
    print -u2 "Installed tree changed across failure point: ${failure_point}"
    diff -u ${before_snapshot} ${after_snapshot} >&2 || true
    exit 1
  }
  assert_private_anchor ${expected_anchor}
  assert_test_root_not_registered ${case_index}-${failure_point}
  print "installer_failure_case=${failure_point}:pass"
  write_private_anchor ${candidate_version}
done

snapshot_global_guard ${global_after}
cmp -s ${global_before} ${global_after} || {
  print -u2 'System anchor, /Applications, Desktop, or Trash changed during the isolated self-test.'
  diff -u ${global_before} ${global_after} >&2 || true
  exit 1
}
assert_test_root_not_registered final

assert_no_transaction_residue
print "installer_failure_injection_cases=${#failure_points[@]}"
print 'installer_failure_injection_audit_points=15'
print 'installer_failure_injection_private_state_unchanged=true'
print 'installer_failure_injection_global_state_unchanged=true'
