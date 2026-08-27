#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
source_file=${script_dir}/InstallerBoundDelete.c
xcrun --find clang >/dev/null
test_tmp_parent=${TMPDIR:-/tmp}
test_tmp_parent=${test_tmp_parent:A}
test_root=$(mktemp -d "${test_tmp_parent}/keep-vault-bound-delete-test.XXXXXXXX")
chmod 0700 ${test_root}
test_root=${test_root:A}
test_root_identity=$(stat -f '%d:%i' ${test_root})

cleanup() {
  local current_identity=''
  if [[ -d ${test_root:-} && ! -L ${test_root:-} \
      && ${test_root:h} == ${test_tmp_parent} \
      && ${test_root:t} == keep-vault-bound-delete-test.* ]]; then
    current_identity=$(stat -f '%d:%i' ${test_root} 2>/dev/null || true)
    if [[ ${current_identity} == ${test_root_identity:-invalid} ]]; then
      rm -rf -- ${test_root}
      return
    fi
  fi
  print -u2 "Refusing to clean a replaced bound-delete self-test root: ${test_root:-missing}"
}
trap cleanup EXIT INT TERM

parent=${test_root}/Applications
quarantine=${test_root}/Quarantine
mkdir -m 0700 -- ${parent} ${quarantine}
parent_identity=$(stat -f '%d:%i' ${parent})
quarantine_identity=$(stat -f '%d:%i' ${quarantine})
parent_device=${parent_identity%%:*}
parent_inode=${parent_identity#*:}
quarantine_device=${quarantine_identity%%:*}
quarantine_inode=${quarantine_identity#*:}

helper=${test_root}/installer-bound-delete
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 ${source_file} -o ${helper}
chmod 0500 ${helper}

delete_expected() {
  local name=$1
  local identity=$2
  ${helper} \
    ${parent} ${name} ${parent_device} ${parent_inode} \
    ${quarantine} ${quarantine_device} ${quarantine_inode} ${identity}
}

print -rn -- 'ordinary-sidecar' > ${parent}/sidecar.sha3
ordinary_identity=$(stat -f '%d:%i' ${parent}/sidecar.sha3)
delete_expected sidecar.sha3 ${ordinary_identity} >/dev/null
[[ ! -e ${parent}/sidecar.sha3 && ! -L ${parent}/sidecar.sha3 ]]

outside_sentinel=${test_root}/outside-sentinel
print -rn -- 'must-survive' > ${outside_sentinel}
mkdir -p ${parent}/Nested.app/Contents/Resources/inner
print -rn -- 'payload' > ${parent}/Nested.app/Contents/Resources/inner/data.bin
ln -s ${outside_sentinel} ${parent}/Nested.app/Contents/Resources/external-link
nested_identity=$(stat -f '%d:%i' ${parent}/Nested.app)
delete_expected Nested.app ${nested_identity} >/dev/null
[[ ! -e ${parent}/Nested.app && ! -L ${parent}/Nested.app \
    && $(<${outside_sentinel}) == must-survive ]]

# Deterministically model the path substitution window: the expected inode is
# retained elsewhere while a foreign object occupies its former public name.
print -rn -- 'expected-object' > ${parent}/raced.sha3
expected_identity=$(stat -f '%d:%i' ${parent}/raced.sha3)
mv ${parent}/raced.sha3 ${test_root}/expected-retained
print -rn -- 'foreign-object-must-survive' > ${parent}/raced.sha3
set +e
delete_expected raced.sha3 ${expected_identity} >${test_root}/mismatch.log 2>&1
mismatch_status=$?
set -e
(( mismatch_status == 68 )) || {
  print -u2 "Identity-mismatch test returned ${mismatch_status}, expected 68."
  sed -n '1,120p' ${test_root}/mismatch.log >&2
  exit 1
}
grep -Fq 'installer_bound_delete_identity_mismatch=true' ${test_root}/mismatch.log
[[ ! -e ${parent}/raced.sha3 && ! -L ${parent}/raced.sha3 \
    && $(<${test_root}/expected-retained) == expected-object ]]
preserved=(${quarantine}/.keep-vault-delete.*(N))
(( ${#preserved[@]} == 1 ))
[[ -f ${preserved[1]} && ! -L ${preserved[1]} \
    && $(<${preserved[1]}) == foreign-object-must-survive ]]

print -rn -- 'mode-guard' > ${parent}/mode.sha3
mode_identity=$(stat -f '%d:%i' ${parent}/mode.sha3)
chmod 0755 ${quarantine}
set +e
delete_expected mode.sha3 ${mode_identity} >${test_root}/mode.log 2>&1
mode_status=$?
set -e
(( mode_status == 66 ))
[[ -f ${parent}/mode.sha3 && $(<${parent}/mode.sha3) == mode-guard ]]
chmod 0700 ${quarantine}

print -rn -- 'parent-guard' > ${parent}/parent.sha3
parent_guard_identity=$(stat -f '%d:%i' ${parent}/parent.sha3)
set +e
${helper} \
  ${parent} parent.sha3 ${parent_device} $(( parent_inode + 1 )) \
  ${quarantine} ${quarantine_device} ${quarantine_inode} ${parent_guard_identity} \
  >${test_root}/parent.log 2>&1
parent_status=$?
set -e
(( parent_status == 65 ))
[[ -f ${parent}/parent.sha3 && $(<${parent}/parent.sha3) == parent-guard ]]

print 'installer_bound_delete_file=true'
print 'installer_bound_delete_recursive_nofollow=true'
print 'installer_bound_delete_identity_mismatch_preserved=true'
print 'installer_bound_delete_directory_guards=true'
