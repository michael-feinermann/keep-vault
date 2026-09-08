# Sourced only after the containing Installer.app has passed the system Apple
# signature requirement in the caller. This file is sealed inside that bundle.
package_fail() {
  print -u2 "INSTALLATION PACKAGE GATE: $*"
  exit 2
}

package_identity() {
  /usr/bin/stat -f '%d:%i:%u:%p:%z:%m:%c:%l' -- "$1" 2>/dev/null
}

package_bundle_identity() {
  local item=$1
  [[ ${item:a} == ${item:A} && -d ${item} && ! -L ${item} ]] || return 1
  local item_mode=$(( 8#$(/usr/bin/stat -f %Lp -- ${item}) ))
  (( (item_mode & 8#022) == 0 )) || return 1
  # macOS may update metadata on the Installer.app directory while executing
  # an already verified helper. The observed ctime-only change must not reject
  # that valid package. Retain every other directory identity field. The root
  # directory and regular helpers still bind ctime; helpers also bind SHA-256.
  # Root-owned read-only staging, Apple signatures and the complete hybrid
  # installation inventory remain separate mandatory gates.
  /usr/bin/stat -f '%d:%i:%u:%p:%z:%m:%l' -- ${item} 2>/dev/null
}

package_regular_identity() {
  local item=$1
  [[ ${item:a} == ${item:A} && -f ${item} && ! -L ${item} ]] || return 1
  [[ $(/usr/bin/stat -f %l -- ${item}) == 1 ]] || return 1
  local item_mode=$(( 8#$(/usr/bin/stat -f %Lp -- ${item}) ))
  (( (item_mode & 8#022) == 0 )) || return 1
  local identity_before item_digest
  identity_before=$(package_identity ${item}) || return 1
  item_digest=$(/usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' \
    /usr/bin/shasum -a 256 -- ${item} | /usr/bin/awk '{print $1}') || return 1
  [[ $(package_identity ${item}) == ${identity_before} ]] || return 1
  print -r -- ${identity_before}:${item_digest}
}

package_require_identity() {
  [[ ${package_root:a} == ${package_root:A} && -d ${package_root} && ! -L ${package_root} \
      && $(package_identity ${package_root}) == ${package_root_identity} ]] \
    || package_fail 'The bound package root changed identity.'
  [[ $(package_bundle_identity ${package_installer}) == ${package_installer_identity} ]] \
    || package_fail 'The bound installer bundle changed identity.'
  [[ $(package_regular_identity ${package_verifier}) == ${package_verifier_identity} ]] \
    || package_fail 'The bound native verifier changed identity.'
  [[ $(package_regular_identity ${package_bound_delete}) == ${package_bound_delete_identity} ]] \
    || package_fail 'The bound rollback helper changed identity.'
}

package_validate_distribution() {
  local target_app=$1
  local source_app=${package_root}/${target_app:t}
  case ${target_app:t} in
    'Keep Vault.app'|'QR-Scanner.app'|'Keep Vault Installer.app') ;;
    *) package_fail 'Unknown app requested for distribution verification.' ;;
  esac
  # syspolicy_check alone accepts some damaged tickets. Bind the exact ticket
  # bytes to the complete, signed post-staple inventory first. That inventory
  # is generated only after the build-side stapler validate gate passes.
  package_run_verifier verify-installation --root ${package_root} --require-root-owned \
    || package_fail 'The post-staple installation inventory changed.'
  local target_ticket=${target_app}/Contents/CodeResources
  local source_ticket=${source_app}/Contents/CodeResources
  local target_identity source_identity
  target_identity=$(package_regular_identity ${target_ticket}) \
    || package_fail 'The target app has no safe, local stapled ticket.'
  source_identity=$(package_regular_identity ${source_ticket}) \
    || package_fail 'The source app has no safe, inventory-bound local ticket.'
  [[ ${target_identity##*:} == ${source_identity##*:} ]] \
    || package_fail 'The target ticket differs from the authenticated release ticket.'
  /usr/bin/syspolicy_check distribution ${target_app} --verbose \
    || package_fail "Current macOS distribution policy rejected ${target_app}"
  package_run_verifier verify-installation --root ${package_root} --require-root-owned \
    || package_fail 'The post-staple installation inventory changed during policy verification.'
  [[ $(package_regular_identity ${target_ticket}) == ${target_identity} \
      && $(package_regular_identity ${source_ticket}) == ${source_identity} ]] \
    || package_fail 'A local ticket changed during policy verification.'
}

package_run_verifier() {
  package_require_identity
  local verifier_status=0
  /usr/bin/env -i PATH='/usr/bin:/bin:/usr/sbin:/sbin' \
    DOTNET_EnableDiagnostics=0 COMPlus_EnableDiagnostics=0 \
    "${package_verifier}" "$@" || verifier_status=$?
  package_require_identity
  (( verifier_status == 0 )) || return ${verifier_status}
}

package_root_identity=$(package_identity ${package_root}) || package_fail 'Cannot bind package root.'
package_installer_identity=$(package_bundle_identity ${package_installer}) || package_fail 'Cannot bind installer bundle.'
package_verifier=${package_installer}/Contents/MacOS/Keep\ Vault\ Release\ Verifier
package_bound_delete=${package_installer}/Contents/MacOS/InstallerBoundDelete
package_verifier_identity=$(package_regular_identity ${package_verifier}) || package_fail 'Native verifier is unsafe.'
package_bound_delete_identity=$(package_regular_identity ${package_bound_delete}) || package_fail 'Native rollback helper is unsafe.'
for package_native in ${package_verifier} ${package_bound_delete}; do
  [[ -x ${package_native} ]] || package_fail "Packaged program is not executable: ${package_native}"
  package_native_details=$(/usr/bin/codesign -dvvv ${package_native} 2>&1) || package_fail 'Cannot read native code signature.'
  [[ ${package_native_details} == *'Authority=Developer ID Application:'* \
      && ${package_native_details} == *'TeamIdentifier=2T6K9PGS55'* \
      && ${package_native_details} == *'flags='*'runtime'* ]] \
    || package_fail 'Packaged native code requires Developer ID and Hardened Runtime.'
done
package_validate_distribution ${package_installer}
package_run_verifier verify-installation --root ${package_root} --require-root-owned \
  || package_fail 'The complete installation inventory did not verify.'
for package_native in ${package_verifier} ${package_bound_delete}; do
  package_run_verifier verify-artifact --payload ${package_native} \
    --sidecar-base ${package_installer}/Contents/Resources/HybridSignatures/${package_native:t} \
    --require-all-sidecars || package_fail 'A packaged native hybrid signature failed.'
done
unset package_native package_native_details
