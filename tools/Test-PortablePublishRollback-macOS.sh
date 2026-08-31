#!/bin/zsh
set -euo pipefail
umask 077

script_dir=${0:A:h}
delete_source=${script_dir}/InstallerBoundDelete.c
test_parent=${TMPDIR:-/tmp}
test_parent=${test_parent:A}
test_root=$(mktemp -d "${test_parent}/keep-vault-portable-rollback-test.XXXXXXXX")
chmod 0700 ${test_root}
test_root=${test_root:A}
test_root_identity=$(stat -f '%d:%i' ${test_root})

cleanup() {
  if [[ -d ${test_root:-} && ! -L ${test_root:-} \
      && ${test_root:h} == ${test_parent} \
      && ${test_root:t} == keep-vault-portable-rollback-test.* \
      && $(stat -f '%d:%i' ${test_root} 2>/dev/null || true) == ${test_root_identity:-invalid} ]]; then
    rm -rf -- ${test_root}
  else
    print -u2 "Refusing to clean a replaced portable-rollback test root: ${test_root:-missing}"
  fi
}
trap cleanup EXIT INT TERM

output=${test_root}/output
quarantine=${test_root}/quarantine
mkdir -m 0700 -- ${output} ${quarantine}
output_identity=$(stat -f '%d:%i' ${output})
quarantine_identity=$(stat -f '%d:%i' ${quarantine})
helper=${test_root}/portable-bound-delete
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 ${delete_source} -o ${helper}

delete_expected() {
  local name=$1
  local identity=$2
  ${helper} \
    ${output} ${name} ${output_identity%%:*} ${output_identity#*:} \
    ${quarantine} ${quarantine_identity%%:*} ${quarantine_identity#*:} \
    ${identity}
}

# A normal interrupted publication is removed recursively without following a
# symbolic link or destroying an outside hard-link alias.
mkdir -p ${output}/partial/inner
print -rn -- payload > ${output}/partial/inner/data
ln ${output}/partial/inner/data ${test_root}/outside-hard-link
print -rn -- outside > ${test_root}/outside-symlink-target
ln -s ${test_root}/outside-symlink-target ${output}/partial/external-link
partial_identity=$(stat -f '%d:%i' ${output}/partial)
delete_expected partial ${partial_identity} >/dev/null
[[ ! -e ${output}/partial \
    && $(<${test_root}/outside-hard-link) == payload \
    && $(<${test_root}/outside-symlink-target) == outside ]]

# Deterministically occupy the published name with another inode after the
# expected object was recorded. Rollback may quarantine that foreign object to
# close the public partial name, but it must never delete or modify it.
print -rn -- expected > ${output}/artifact.zip
expected_identity=$(stat -f '%d:%i' ${output}/artifact.zip)
mv ${output}/artifact.zip ${test_root}/expected-retained
print -rn -- foreign-must-survive > ${output}/artifact.zip
set +e
delete_expected artifact.zip ${expected_identity} >${test_root}/mismatch.log 2>&1
mismatch_status=$?
set -e
(( mismatch_status == 68 ))
preserved=(${quarantine}/.keep-vault-delete.*(N))
(( ${#preserved[@]} == 1 ))
[[ ! -e ${output}/artifact.zip \
    && $(<${test_root}/expected-retained) == expected \
    && $(<${preserved[1]}) == foreign-must-survive ]]

print 'portable_rollback_recursive_nofollow=true'
print 'portable_rollback_hard_link_target_preserved=true'
print 'portable_rollback_substitution_preserved=true'
