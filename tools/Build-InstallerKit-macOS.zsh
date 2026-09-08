# Internal functions sourced by the already-sanitized release builder.
# Signing material stays in its existing protected run_hybrid_signer boundary.
sign_installation_artifact() {
  local target=$1
  local pin_label=$2
  local -a arguments=(
    ${signer_dll} sign --pfx ${pfx_path}
    ${mldsa_key_arguments[@]} ${pfx_password_arguments[@]}
    --mldsa-public-key ${mldsa_public_key}
    --reference-library ${repo_root}/KeepVaultMac/Native/$([[ ${architecture} == universal ]] && print osx-universal || print osx-arm64)/libmldsa87_ref.dylib
    --policy ${mac_project}/Directory.Build.props
    --launcher-pins ${build_root}/${pin_label}.swift
    --target ${target}
  )
  (cd ${mac_project}; run_hybrid_signer ${arguments[@]})
}

build_installer_kit() {
  # Exercise the actual codesign and ACL command syntax before signing an
  # installer. These tests use disposable local fixtures without authorization.
  /usr/bin/python3 ${script_dir}/Test-InstallerEntry-macOS.py || return $?
  /usr/bin/python3 ${script_dir}/Test-PackageMode-macOS.py || return $?
  installer_app=${dist_stage}/Keep\ Vault\ Installer.app
  local installer_macos=${installer_app}/Contents/MacOS
  local installer_resources=${installer_app}/Contents/Resources
  mkdir -p ${installer_macos} ${installer_resources}/tools ${installer_resources}/HybridSignatures
  local script
  for script in Install-KeepVault-macOS.sh Verify-KeepVault-macOS.sh Verify-QR-Scanner-macOS.sh Verify-ReleasePairMetadata-macOS.sh PackageRuntime-macOS.sh; do
    [[ -f ${script_dir}/${script} && ! -L ${script_dir}/${script} ]] || return 2
    ditto ${script_dir}/${script} ${installer_resources}/tools/${script}
    if [[ ${script} == PackageRuntime-macOS.sh ]]; then
      chmod 0644 ${installer_resources}/tools/${script}
    else
      chmod 0755 ${installer_resources}/tools/${script}
    fi
  done
  sed -e "s/@@MARKETING_VERSION@@/${marketing_version}/g" \
    -e "s/@@BUILD_VERSION@@/${build_version}/g" \
    ${packaging_dir}/Installer.Info.plist.template > ${installer_app}/Contents/Info.plist
  plutil -lint ${installer_app}/Contents/Info.plist

  local runtime slice publish_dir
  local -a runtimes=(osx-arm64) verifier_slices=() entry_slices=() delete_slices=()
  [[ ${architecture} == universal ]] && runtimes+=(osx-x64)
  for runtime in ${runtimes[@]}; do
    publish_dir=${build_root}/installer-verifier-${runtime}
    (cd ${repo_root}/KeepVaultMac.ReleaseVerifier
      run_dotnet_clean publish KeepVaultMac.ReleaseVerifier.csproj -c Release -r ${runtime} \
        --artifacts-path ${private_verifier_artifacts} --no-restore --self-contained true --nologo \
        -p:PublishAot=true -p:PublishTrimmed=true -p:StripSymbols=true \
        -p:UseSharedCompilation=false --disable-build-servers -o ${publish_dir})
    verifier_slices+=(${publish_dir}/Keep\ Vault\ Release\ Verifier)
  done
  local arch
  for arch in ${launcher_architectures[@]}; do
    xcrun swiftc -target ${arch}-apple-macos14.0 -parse-as-library -O -whole-module-optimization \
      ${packaging_dir}/InstallerMain.swift -framework AppKit -framework Security \
      -o ${build_root}/installer-entry-${arch}
    xcrun clang -arch ${arch} -mmacosx-version-min=14.0 -std=c17 -Wall -Wextra -Werror -O2 \
      -fstack-protector-strong ${script_dir}/InstallerBoundDelete.c -o ${build_root}/installer-delete-${arch}
    entry_slices+=(${build_root}/installer-entry-${arch})
    delete_slices+=(${build_root}/installer-delete-${arch})
  done
  if [[ ${architecture} == universal ]]; then
    xcrun lipo -create ${verifier_slices[@]} -output ${installer_macos}/Keep\ Vault\ Release\ Verifier
    xcrun lipo -create ${entry_slices[@]} -output ${installer_macos}/Keep\ Vault\ Installer
    xcrun lipo -create ${delete_slices[@]} -output ${installer_macos}/InstallerBoundDelete
  else
    ditto ${verifier_slices[1]} ${installer_macos}/Keep\ Vault\ Release\ Verifier
    ditto ${entry_slices[1]} ${installer_macos}/Keep\ Vault\ Installer
    ditto ${delete_slices[1]} ${installer_macos}/InstallerBoundDelete
  fi
  chmod 0755 ${installer_macos}/Keep\ Vault\ Release\ Verifier ${installer_macos}/Keep\ Vault\ Installer ${installer_macos}/InstallerBoundDelete
  sign_macho ${installer_macos}/Keep\ Vault\ Release\ Verifier ${bundle_identifier}.releaseverifier
  sign_macho ${installer_macos}/InstallerBoundDelete ${bundle_identifier}.installer.bounddelete
  local native suffix
  for native in ${installer_macos}/Keep\ Vault\ Release\ Verifier ${installer_macos}/InstallerBoundDelete; do
    sign_installation_artifact ${native} InstallerNativePins
    for suffix in .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
      mv ${native}${suffix} ${installer_resources}/HybridSignatures/${native:t}${suffix}
    done
  done
  codesign ${apple_keychain_codesign_args[@]} --force --sign ${identity} --options runtime \
    ${timestamp_arguments[@]} --identifier ${bundle_identifier}.installer ${installer_app}
  codesign --verify --strict --deep ${installer_app}
  for native in ${installer_macos}/*; do
    xcrun lipo ${native} -verify_arch ${launcher_architectures[@]}
  done
  ditto ${packaging_dir}/INSTALLATION.txt ${dist_stage}/INSTALLATION.txt
}

stage_installation_kit() {
  local root=$1
  ditto ${installer_app} ${root}/Keep\ Vault\ Installer.app
  ditto ${dist_stage}/INSTALLATION.txt ${root}/INSTALLATION.txt
  /usr/bin/python3 ${script_dir}/Write-InstallationManifest-macOS.py \
    --root ${root} --version ${marketing_version} --build ${build_version}
  sign_installation_artifact ${root}/installation-manifest.json InstallationManifestPins
  ${installer_app}/Contents/MacOS/Keep\ Vault\ Release\ Verifier verify-installation --root ${root}
  # The directory published beside the ZIP carries the same installation kit.
  local suffix
  for suffix in '' .sha3 .skein .khsig .sha3.khsig .skein.khsig; do
    ditto ${root}/installation-manifest.json${suffix} ${dist_stage}/installation-manifest.json${suffix}
  done
}
