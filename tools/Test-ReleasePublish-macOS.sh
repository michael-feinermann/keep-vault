#!/bin/zsh
set -euo pipefail
umask 077

script_dir=${0:A:h}
rename_source=${script_dir}/ReleasePublishRename.c
delete_source=${script_dir}/InstallerBoundDelete.c
test_parent=${TMPDIR:-/tmp}
test_parent=${test_parent:A}
test_root=$(mktemp -d "${test_parent}/keep-vault-release-publish-test.XXXXXXXX")
chmod 0700 ${test_root}
test_root=${test_root:A}
test_root_identity=$(stat -f '%d:%i' ${test_root})

cleanup() {
  if [[ -d ${test_root:-} && ! -L ${test_root:-} \
      && ${test_root:h} == ${test_parent} \
      && ${test_root:t} == keep-vault-release-publish-test.* \
      && $(stat -f '%d:%i' ${test_root} 2>/dev/null || true) == ${test_root_identity:-invalid} ]]; then
    rm -rf -- ${test_root}
  else
    print -u2 "Refusing to clean a replaced release-publish test root: ${test_root:-missing}"
  fi
}
trap cleanup EXIT INT TERM

rename_helper=${test_root}/release-publish-rename
delete_helper=${test_root}/installer-bound-delete
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 \
  -DKEEPVAULT_RELEASE_PUBLISH_TEST_HOOKS=1 \
  ${rename_source} -o ${rename_helper}
xcrun clang -std=c17 -Wall -Wextra -Werror -O2 ${delete_source} -o ${delete_helper}

parent=${test_root}/publish
quarantine=${test_root}/quarantine
mkdir -m 0700 -- ${parent} ${quarantine}
parent_identity=$(stat -f '%d:%i' ${parent})
quarantine_identity=$(stat -f '%d:%i' ${quarantine})

mkdir ${parent}/current ${parent}/stage
print -rn -- old > ${parent}/current/value
print -rn -- new > ${parent}/stage/value
ln ${parent}/current/value ${test_root}/old-hard-link
current_identity=$(stat -f '%d:%i' ${parent}/current)
stage_identity=$(stat -f '%d:%i' ${parent}/stage)
${rename_helper} swap ${parent} stage ${parent} current \
  ${parent_identity} ${parent_identity} ${stage_identity} ${current_identity} >/dev/null
[[ $(<${parent}/current/value) == new \
    && $(<${parent}/stage/value) == old \
    && $(stat -f '%d:%i' ${parent}/current) == ${stage_identity} \
    && $(stat -f '%d:%i' ${parent}/stage) == ${current_identity} ]]

${delete_helper} \
  ${parent} stage ${parent_identity%%:*} ${parent_identity#*:} \
  ${quarantine} ${quarantine_identity%%:*} ${quarantine_identity#*:} \
  ${current_identity} >/dev/null
[[ ! -e ${parent}/stage && $(<${test_root}/old-hard-link) == old ]]

# A substituted stage must be rejected before the atomic exchange and neither
# the old public tree nor the foreign replacement may be removed.
mkdir ${parent}/expected-stage
print -rn -- expected > ${parent}/expected-stage/value
expected_identity=$(stat -f '%d:%i' ${parent}/expected-stage)
mv ${parent}/expected-stage ${test_root}/retained-stage
mkdir ${parent}/expected-stage
print -rn -- foreign-must-survive > ${parent}/expected-stage/value
set +e
${rename_helper} swap ${parent} expected-stage ${parent} current \
  ${parent_identity} ${parent_identity} ${expected_identity} ${stage_identity} \
  >${test_root}/substitution.log 2>&1
substitution_status=$?
set -e
(( substitution_status == 66 ))
[[ $(<${parent}/current/value) == new \
    && $(<${parent}/expected-stage/value) == foreign-must-survive \
    && $(<${test_root}/retained-stage/value) == expected ]]

mkdir ${parent}/first-stage ${parent}/raced-target
print -rn -- first > ${parent}/first-stage/value
print -rn -- raced > ${parent}/raced-target/value
first_identity=$(stat -f '%d:%i' ${parent}/first-stage)
set +e
${rename_helper} exclusive ${parent} first-stage ${parent} raced-target \
  ${parent_identity} ${parent_identity} ${first_identity} - >${test_root}/exclusive-race.log 2>&1
exclusive_race_status=$?
set -e
(( exclusive_race_status == 67 ))
[[ $(<${parent}/first-stage/value) == first && $(<${parent}/raced-target/value) == raced ]]

${rename_helper} exclusive ${parent} first-stage ${parent} first-release \
  ${parent_identity} ${parent_identity} ${first_identity} - >/dev/null
[[ ! -e ${parent}/first-stage \
    && $(<${parent}/first-release/value) == first \
    && $(stat -f '%d:%i' ${parent}/first-release) == ${first_identity} ]]

# Deterministically replace the source after the helper's identity precheck.
# The unexpected inode may be moved momentarily by the kernel primitive, but
# the helper must move it back before returning and leave no public target.
mkdir ${parent}/race-stage
print -rn -- expected-race > ${parent}/race-stage/value
race_identity=$(stat -f '%d:%i' ${parent}/race-stage)
race_ready=${test_root}/race-ready
race_continue=${test_root}/race-continue
KEEPVAULT_RENAME_TEST_READY=${race_ready} \
KEEPVAULT_RENAME_TEST_CONTINUE=${race_continue} \
  ${rename_helper} exclusive ${parent} race-stage ${parent} race-release \
    ${parent_identity} ${parent_identity} ${race_identity} - \
    >${test_root}/mid-rename-race.log 2>&1 &
race_pid=$!
for attempt in {1..1000}; do
  [[ -e ${race_ready} ]] && break
  sleep 0.01
done
[[ -e ${race_ready} ]]
mv ${parent}/race-stage ${test_root}/retained-race-stage
mkdir ${parent}/race-stage
print -rn -- foreign-race > ${parent}/race-stage/value
touch ${race_continue}
set +e
wait ${race_pid}
race_status=$?
set -e
(( race_status == 68 ))
[[ ! -e ${parent}/race-release \
    && $(<${parent}/race-stage/value) == foreign-race \
    && $(<${test_root}/retained-race-stage/value) == expected-race ]]

source_parent=${test_root}/cross-directory-stage
mkdir -m 0700 ${source_parent}
source_parent_identity=$(stat -f '%d:%i' ${source_parent})
print -rn -- portable-zip > ${source_parent}/artifact.zip
file_identity=$(stat -f '%d:%i' ${source_parent}/artifact.zip)
${rename_helper} exclusive \
  ${source_parent} artifact.zip ${parent} published.zip \
  ${source_parent_identity} ${parent_identity} ${file_identity} - >/dev/null
[[ ! -e ${source_parent}/artifact.zip \
    && -f ${parent}/published.zip \
    && $(<${parent}/published.zip) == portable-zip \
    && $(stat -f '%d:%i' ${parent}/published.zip) == ${file_identity} ]]

print 'release_publish_atomic_swap=true'
print 'release_publish_stage_substitution_rejected=true'
print 'release_publish_mid_rename_substitution_rolled_back=true'
print 'release_publish_first_release_exclusive=true'
print 'release_publish_cross_directory_file=true'
print 'release_publish_old_hard_link_preserved=true'
