#!/usr/bin/env python3
"""Compare already-produced public GUI files; do not execute the product or tests."""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import os
import stat
import subprocess
import time

REPO = Path('/Users/michael/Developer/GPT-Codex/Kalyna')
OLD = REPO / 'work/v13-evidence/rev12-final-resume-20261011'
PUBLIC = OLD / 'native-gui-public'
OBS = OLD / 'native-gui-observations'
SOURCE = PUBLIC / 'paranoia-multichunk-source'
PREPARATION = OBS / 'paranoia-multichunk-fixture-preparation-20261011T101628290074Z'
MANIFEST = PREPARATION / 'source-manifest.json'
ORIGINAL_COMPARER = PREPARATION / 'compare-public-paranoia-multichunk-tree.py'
LIBRARY = OBS / 'compare-native-gui-public-tree.py'
RECEIPTS = REPO / 'work/v13-evidence/rev12-final-resume-20261012-native-paranoia'
PRODUCT_HEAD = 'ea0eeecface1a8d16760676c1d6a428baef350c0'
DOCUMENT_HEAD = '2273d4d20b754b68b1daf1b46c03ce0629d075fc'
TEST_SCHEDULER = 'KeepVaultMac.Tests/TestScheduler.cs'
MANIFEST_SHA256 = '4fd74b8791e5a7613753083625475ae326b43c50850a9139b51687655198ff8a'
LIBRARY_SHA256 = '2e9d09474cc7f3b106a2a63b47049b4c20fa5b6434ed5a1293d34049a5f279b1'
ORIGINAL_COMPARER_SHA256 = '3e6e8db4c8829807717e1c0620c409d1cfa2bdb43c02be067408784b59b6b25d'
SCHEDULER_SHA256 = '68dc270f22a649bcf53bbe61f7c6b6344b78c20fe0b962417bb131f73f4a3d0d'


def git(*arguments):
    return subprocess.run(['/usr/bin/git', *arguments], cwd=REPO, check=True,
                          capture_output=True).stdout


def retained_tree(commit):
    raw = git('ls-tree', '-r', '-z', '--full-tree', commit)
    records = [record for record in raw.split(b'\0') if record]
    retained = []
    for record in records:
        metadata, name = record.split(b'\t', 1)
        path = name.decode('utf-8')
        if not path.startswith('docs/') and path != TEST_SCHEDULER:
            retained.append(record)
    return b'\0'.join(retained) + b'\0'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('outputRoot', help='Absolute owned extraction root below native-gui-public')
    parser.add_argument('archivePath', help='Absolute already-created Paranoia .kzpaq below native-gui-public')
    args = parser.parse_args()
    output, archive = Path(args.outputRoot), Path(args.archivePath)
    for path in (PUBLIC, OBS, RECEIPTS, SOURCE, output, archive):
        assert path.is_absolute() and path.resolve(strict=True) == path
        assert path.lstat().st_uid == os.getuid()
    for path in (SOURCE, output, archive):
        assert path.is_relative_to(PUBLIC)
    assert all(stat.S_ISDIR(path.lstat().st_mode) for path in (PUBLIC, OBS, RECEIPTS, SOURCE, output))
    assert archive.suffix == '.kzpaq'
    assert output != SOURCE and not output.is_relative_to(SOURCE) and not SOURCE.is_relative_to(output)
    assert not archive.is_relative_to(SOURCE) and not archive.is_relative_to(output)
    helper = Path(__file__).resolve(strict=True)
    assert helper.parent == RECEIPTS
    initial_head = git('rev-parse', 'HEAD').decode('ascii').strip()
    assert initial_head == DOCUMENT_HEAD

    library_raw = LIBRARY.read_bytes()
    assert hashlib.sha256(library_raw).hexdigest() == LIBRARY_SHA256
    namespace = {'__name__': '_frozen_public_inventory_library', '__file__': str(LIBRARY)}
    exec(compile(library_raw, str(LIBRARY), 'exec'), namespace)
    pin, inventory, reduced, utc = (namespace[name] for name in ('file_pin', 'inventory', 'reduced', 'utc'))
    started, clock = utc(), time.monotonic()
    root_pins = {str(path): (path.lstat().st_dev, path.lstat().st_ino) for path in (PUBLIC, OBS, RECEIPTS)}
    manifest_pin, manifest_raw = pin(MANIFEST, True)
    original_pin, library_pin, helper_pin = pin(ORIGINAL_COMPARER), pin(LIBRARY), pin(helper)
    scheduler_pin = pin(REPO / TEST_SCHEDULER)
    assert manifest_pin['sha256'] == MANIFEST_SHA256
    assert original_pin['sha256'] == ORIGINAL_COMPARER_SHA256
    assert library_pin['sha256'] == LIBRARY_SHA256
    assert scheduler_pin['sha256'] == SCHEDULER_SHA256
    expected = json.loads(manifest_raw)
    assert expected['sourceHeadBefore'] == expected['sourceHeadAfter'] == PRODUCT_HEAD
    assert expected['fixtureRoot'] == str(SOURCE)
    assert expected['sourceFileCount'] == 7 and expected['sourceDirectoryCountIncludingRoot'] == 16
    assert expected['sourceBytes'] == 134222033

    diff_raw = git('diff', '--name-only', '--no-renames', '-z', PRODUCT_HEAD, DOCUMENT_HEAD)
    changed_paths = [path.decode('utf-8') for path in diff_raw.split(b'\0') if path]
    committed_change_scope = (TEST_SCHEDULER in changed_paths and
                              all(path == TEST_SCHEDULER or path.startswith('docs/') for path in changed_paths))
    original_tree, document_tree = retained_tree(PRODUCT_HEAD), retained_tree(DOCUMENT_HEAD)
    tracked_worktree_raw = git('diff', '--name-only', '--no-renames', '-z', 'HEAD')
    tracked_worktree_paths = [path.decode('utf-8') for path in tracked_worktree_raw.split(b'\0') if path]
    before_source, before_output = inventory(SOURCE), inventory(output)
    simple_source, simple_output = reduced(before_source), reduced(before_output)
    expected_source = {'directories': expected['directories'], 'files': expected['files']}
    root = SOURCE.name
    expected_directories = sorted(['.'] + [root if name == '.' else root + '/' + name
                                          for name in expected_source['directories']])
    expected_files = dict(sorted((root + '/' + name, file) for name, file in expected_source['files'].items()))
    sidecar = Path(str(archive) + '.kpar2')
    artifacts = {'archive': pin(archive), 'kpar2': pin(sidecar)}
    final_head = git('rev-parse', 'HEAD').decode('ascii').strip()
    checks = {
        'originalFixtureManifestAndComparisonHelpersRemainExact':
            manifest_pin == pin(MANIFEST) and original_pin == pin(ORIGINAL_COMPARER) and library_pin == pin(LIBRARY),
        'originalFixtureCreationBoundToBuild20ProductHead':
            expected['sourceHeadBefore'] == expected['sourceHeadAfter'] == PRODUCT_HEAD,
        'currentDocumentHeadDeclaredAndStable': initial_head == final_head == DOCUMENT_HEAD,
        'gitDiffChangesOnlyDiagnosticSchedulerAndDocumentation': committed_change_scope,
        'everyOtherCommittedTreeEntryUnchangedSinceBuild20ProductHead': original_tree == document_tree,
        'trackedWorktreeHasNoChanges': not tracked_worktree_paths and tracked_worktree_raw == git('diff', '--name-only', '--no-renames', '-z', 'HEAD'),
        'sourceMatchesPredeclaredPublicFixture': simple_source == expected_source,
        'exactSingleArchiveRootAndCompleteOutputTree':
            simple_output == {'directories': expected_directories, 'files': expected_files},
        'allFileSha256AndSizesEqual': simple_output['files'] == expected_files,
        'allEmptyNestedHiddenUnicodeLongDirectoriesEqual': simple_output['directories'] == expected_directories,
        'large128MiBPublicFilePresentAndHashEqual':
            simple_output['files'].get(root + '/public-deterministic-128MiB.bin') ==
            expected_source['files']['public-deterministic-128MiB.bin'],
        'archiveAndKpar2PresentNonempty': all(artifact['bytes'] > 0 for artifact in artifacts.values()),
        'sourceOutputArtifactsAndHelperStable':
            before_source == inventory(SOURCE) and before_output == inventory(output) and
            artifacts == {'archive': pin(archive), 'kpar2': pin(sidecar)} and
            helper_pin == pin(helper) and scheduler_pin == pin(REPO / TEST_SCHEDULER),
        'evidenceRootDirectoryIdentitiesStable': all(
            identity == (Path(path).lstat().st_dev, Path(path).lstat().st_ino)
            for path, identity in root_pins.items()),
    }
    result = {
        'schemaVersion': 2,
        'status': 'PUBLIC_PARANOIA_MULTICHUNK_FILESYSTEM_COMPARISON_PASS' if all(checks.values()) else
                  'PUBLIC_PARANOIA_MULTICHUNK_FILESYSTEM_COMPARISON_FAIL',
        'actualStartedUtc': started, 'actualCompletedUtc': utc(),
        'actualComparerPid': os.getpid(), 'actualComparerParentPid': os.getppid(),
        'comparisonWallSeconds': time.monotonic() - clock,
        'sourceHeadBefore': initial_head, 'sourceHeadAfter': final_head,
        'fixtureCreationProductHead': PRODUCT_HEAD, 'declaredCurrentDocumentHead': DOCUMENT_HEAD,
        'gitProvenance': {
            'diffCommand': ['git', 'diff', '--name-only', '--no-renames', '-z', PRODUCT_HEAD, DOCUMENT_HEAD],
            'changedPaths': changed_paths, 'diffNameListSha256': hashlib.sha256(diff_raw).hexdigest(),
            'retainedTreeDefinition': 'Every tracked tree entry excluding docs/ and KeepVaultMac.Tests/TestScheduler.cs',
            'retainedProductHeadTreeSha256': hashlib.sha256(original_tree).hexdigest(),
            'retainedDocumentHeadTreeSha256': hashlib.sha256(document_tree).hexdigest(),
            'trackedWorktreeChangedPaths': tracked_worktree_paths,
            'diagnosticSchedulerPin': scheduler_pin,
            'interpretation': 'Product tree entries are unchanged. This does not independently identify the running installed app.',
        },
        'sourcePath': str(SOURCE), 'outputPath': str(output), 'expectedArchiveRoot': root,
        'sourceBytes': expected['sourceBytes'], 'sourceFileCount': expected['sourceFileCount'],
        'sourceDirectoryCountIncludingRoot': expected['sourceDirectoryCountIncludingRoot'],
        'outputDirectoryCountIncludingOuterRoot': len(expected_directories),
        'scope': 'Read-only filesystem comparison of already-produced owned public native GUI files; only a new receipt is written. No product, GUI, benchmark or test execution.',
        'guiExecutionClaimed': False, 'checks': checks,
        'sourceInventory': before_source, 'outputInventory': before_output, 'artifactPins': artifacts,
        'fixtureManifestPin': manifest_pin, 'originalComparisonHelperPin': original_pin,
        'comparisonHelperPin': helper_pin, 'frozenInventoryLibraryPin': library_pin,
        'limitations': [
            'Archive/KPAR2 presence and hashes do not independently prove native creation, authenticated repair or GUI progress.',
            'Actual encrypted chunk count, ETA and cancellation require separate native observations.',
            'The original fixture, manifest and helpers are preserved without rebinding their historical receipts.',
            'Only public fixture and artifacts are read; no PDF, factors or private keys are read.',
        ],
    }
    raw = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    target = RECEIPTS / ('filesystem-comparison-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'receipt': str(target), 'receiptSha256': hashlib.sha256(raw).hexdigest(),
                      'status': result['status'], 'checks': checks, 'sourceBytes': expected['sourceBytes'],
                      'sourceFileCount': expected['sourceFileCount'],
                      'sourceDirectoryCountIncludingRoot': expected['sourceDirectoryCountIncludingRoot'],
                      'outputDirectoryCountIncludingOuterRoot': len(expected_directories),
                      'archiveRoot': root, 'artifactPins': artifacts}, ensure_ascii=False))
    return 0 if all(checks.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
