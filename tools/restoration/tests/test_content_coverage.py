"""Declared package joins exercise the production CLI and real file reads."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('reconcile', Path(__file__).parents[1] / 'reconcile.py')
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


class ContentCoverageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.tree = self.base / 'tree'
        self.tree.mkdir()
        self.files = {}
        for name, data in [('base.ifs', b'base'), ('base.1.ifs', b'segment'), ('addon.ifs', b'addon')]:
            (self.tree / name).write_bytes(data)
            self.files[name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        self.manifest = self.base / 'manifest.json'
        self.manifest.write_text(json.dumps({'files': self.files}))
        self.content = self.base / 'content.json'
        self.inventory = {'targetVersion': '3.19.26.22 / fastfile v461',
                          'maps': [{'internalId': 'mp_fixture', 'recordedPackages': [
                              {'relativePath': p, **self.files[p]} for p in ('base.ifs', 'base.1.ifs')]}],
                          'specialModes': [{'internalId': 'zhunt', 'recordedAddons': [
                              {'relativePath': 'addon.ifs', 'mapId': 'mp_fixture', **self.files['addon.ifs']}]},
                              {'internalId': 'zsurv', 'recordedAddons': []}],
                          'standardModes': [{'slot': 'STD-04', 'confirmedDisplayName': None, 'internalId': None}]}
        self.write_content()

    def write_content(self):
        self.content.write_text(json.dumps(self.inventory))

    def run_cli(self, **changes):
        output = self.base / 'report.json'
        args = ['--manifest', str(self.manifest), '--content-inventory', str(self.content),
                '--output', str(output)]
        for tree in ('original', 'archive-tree', 'restoration'):
            args += ['--' + tree, str(self.tree)]
        args += changes.get('args', [])
        code = r.main(args)
        return code, json.loads(output.read_text()) if output.exists() else None

    def test_cli_joins_all_segments_without_claiming_gameplay(self):
        code, report = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(report['entryCount'], 3)
        coverage = report['contentCoverage']
        self.assertEqual(coverage['inventorySha256'], hashlib.sha256(self.content.read_bytes()).hexdigest())
        self.assertTrue(coverage['referencesConsistent'])
        group = coverage['maps'][0]
        self.assertEqual(group['coverage']['restoration'], {
            'packageCount': 2, 'matchingPackages': 2, 'recordedPackagesMatch': True})
        self.assertEqual(group['runtimeStatus'], 'unverified')
        self.assertEqual(group['dependencyGraph'], 'unavailable')
        self.assertEqual(coverage['specialModes'][0]['mapEligibility'], 'unverified')
        self.assertFalse(coverage['specialModes'][1]['coverage']['restoration']['recordedPackagesMatch'])
        self.assertIsNone(coverage['standardModes'][0]['confirmedDisplayName'])
        self.assertEqual(report['gameCompletion'], 'unverified')
        self.assertTrue(all(v['status'] == 'unknown' for e in report['entries'] for v in e['stages'].values()))

    def test_missing_segment_prevents_package_match(self):
        (self.tree / 'base.1.ifs').unlink()
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        group = report['contentCoverage']['maps'][0]
        self.assertEqual(group['coverage']['original']['matchingPackages'], 1)
        self.assertFalse(group['coverage']['original']['recordedPackagesMatch'])
        self.assertEqual(group['packages'][1]['fileChecks']['original']['status'], 'missing')

    def test_corrupt_addon_is_visible_independently_of_base(self):
        (self.tree / 'addon.ifs').write_bytes(b'wrong')
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        self.assertTrue(report['contentCoverage']['maps'][0]['coverage']['restoration']['recordedPackagesMatch'])
        self.assertFalse(report['contentCoverage']['specialModes'][0]['coverage']['restoration']['recordedPackagesMatch'])

    def test_metadata_conflict_fails_even_when_files_match_manifest(self):
        self.inventory['maps'][0]['recordedPackages'][0]['sha256'] = '0' * 64
        self.write_content()
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(report['contentCoverage']['issues'][0]['status'], 'metadata_conflict')
        self.assertFalse(report['contentCoverage']['maps'][0]['coverage']['original']['recordedPackagesMatch'])

    def test_absent_manifest_reference_is_not_dropped(self):
        self.inventory['maps'][0]['recordedPackages'][0]['relativePath'] = 'unlisted.ifs'
        self.write_content()
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        coverage = report['contentCoverage']
        self.assertEqual(coverage['issues'][0]['status'], 'absent_from_manifest')
        self.assertEqual(len(coverage['maps'][0]['packages']), 2)
        self.assertEqual(report['entryCount'], 3)

    def test_unknown_addon_map_is_explicit(self):
        self.inventory['specialModes'][0]['recordedAddons'][0]['mapId'] = 'not_in_roster'
        self.write_content()
        code, report = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(report['contentCoverage']['issues'][0]['status'], 'unknown_map_reference')

    def test_omitted_trees_never_match(self):
        report = r.reconcile(self.files, {'original': None}, 'hash')
        coverage = r.content_coverage(report, self.inventory, 'inventory-hash')
        self.assertFalse(coverage['maps'][0]['coverage']['original']['recordedPackagesMatch'])
        self.assertEqual(coverage['maps'][0]['packages'][0]['fileChecks']['original']['status'], 'unavailable')

    def test_malformed_schema_and_unsafe_references(self):
        original = copy.deepcopy(self.inventory)
        cases = []
        for path, value in [('targetVersion', 'QA 3.3.3.3'), ('maps', []), ('specialModes', None),
                            ('extraction', {'baseMapIds': 89}), ('extraction', {'matchedIfsFiles': 132}),
                            ('extraction', {'baseMapIds': True}), ('standardModes', [None])]:
            changed = copy.deepcopy(original); changed[path] = value; cases.append(changed)
        for key, value in [('relativePath', '../outside'), ('relativePath', 'CON.ifs'),
                           ('size', True), ('sha256', 'bad')]:
            changed = copy.deepcopy(original); changed['maps'][0]['recordedPackages'][0][key] = value; cases.append(changed)
        changed = copy.deepcopy(original); changed['maps'] *= 2; cases.append(changed)
        changed = copy.deepcopy(original); changed['maps'][0]['recordedPackages'] *= 2; cases.append(changed)
        changed = copy.deepcopy(original); del changed['specialModes'][0]['recordedAddons'][0]['mapId']; cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed):
                self.content.write_text(json.dumps(changed))
                with self.assertRaises(ValueError): r.load_content_inventory(self.content)

    def test_duplicate_json_keys_rejected(self):
        self.content.write_text('{"maps":[],"maps":[]}')
        with self.assertRaisesRegex(ValueError, 'duplicate'): r.load_content_inventory(self.content)

    def test_tsv_cannot_silently_omit_content_coverage(self):
        code, report = self.run_cli(args=['--format', 'tsv'])
        self.assertEqual(code, 2)
        self.assertIsNone(report)

    def test_inventory_cannot_be_replaced(self):
        before = self.content.read_bytes()
        code = r.main(['--manifest', str(self.manifest), '--content-inventory', str(self.content),
                       '--output', str(self.content)])
        self.assertEqual(code, 2)
        self.assertEqual(self.content.read_bytes(), before)

    def test_existing_report_and_source_bytes_preserved(self):
        before = {p: (self.tree / p).read_bytes() for p in self.files}
        self.assertEqual(self.run_cli()[0], 0)
        report = (self.base / 'report.json').read_bytes()
        self.assertEqual(self.run_cli()[0], 2)
        self.assertEqual((self.base / 'report.json').read_bytes(), report)
        self.assertEqual({p: (self.tree / p).read_bytes() for p in self.files}, before)


if __name__ == '__main__':
    unittest.main()
