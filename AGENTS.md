# Repository working instructions

## Windows development workspace

For work on Michael's Windows workstation, the canonical checkout is `C:\Dev\Kalyna`.
Always run development, builds, tests and release preparation from this checkout.
Do not use the historical OneDrive checkout as an active workspace.

Never develop or build this project inside a OneDrive-synchronized directory.
Keep isolated release source snapshots, build outputs and review evidence below
`C:\Dev\Kalyna\work` (and the repository's normal ignored output directories).
On CI and other operating systems, use an ordinary local, non-synchronized checkout.

## Windows release reference and evidence

The macOS GitHub v5.0.2 implementation is the Windows behavior and GUI design
reference. Obtain separate Windows build, security, GUI and release evidence.
Read `docs/KEEP_VAULT_5_0_2_WINDOWS_AUDIT.md` when working on Windows 5.0.2.
A partial native tool set or an unresolved quarantined component is not a
release-ready artifact. Preserve the existing macOS release tag and assets.

Never store private release keys, wrapping keys or plaintext passwords in Git,
process arguments, logs or temporary files. The release key directory is external
to the repository and supplied explicitly to the signing tools.
