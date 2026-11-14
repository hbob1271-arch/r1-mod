import copy
import json
import unittest
import test_content_coverage as fixtures

r = fixtures.r


class DependencyValidationTests(unittest.TestCase):
    setUp = fixtures.ContentCoverageTests.setUp
    write_content = fixtures.ContentCoverageTests.write_content
    run_cli = fixtures.ContentCoverageTests.run_cli
    # Reuse actual temporary byte fixtures and production CLI, not mocked file checks.
    def validation(self):
        code, report = self.run_cli()
        return code, report['contentValidation']

    def test_all_modes_and_unresolved_exports_preserved(self):
        _, v = self.validation()
        self.assertEqual(len(v['records']), 4)  # map, two specials, one standard fixture slot
        by_id = {x['id']: x for x in v['records']}
        self.assertEqual(by_id['zhunt']['rootPackages'], ['addon.ifs', 'base.1.ifs', 'base.ifs'])
        self.assertTrue(by_id['zhunt']['unresolvedDependencies'])
        self.assertFalse(by_id['zhunt']['declaredDependenciesVerified']['original'])
        self.assertIsNone(by_id['STD-04']['internalId'])
        self.assertEqual(by_id['STD-04']['runtimeStatus'], 'unverified')

    def test_valid_explicit_dependencies_and_no_runtime_promotion(self):
        for p in self.inventory['maps'][0]['recordedPackages']: p['dependencies'] = []
        addon = self.inventory['specialModes'][0]['recordedAddons'][0]
        addon['dependencies'] = ['base.ifs']
        self.write_content()
        _, v = self.validation()
        mode = next(x for x in v['records'] if x['id'] == 'zhunt')
        self.assertEqual(mode['dependencyEdges'], [{'from': 'addon.ifs', 'to': 'base.ifs'}])
        self.assertTrue(mode['declaredDependenciesVerified']['restoration'])
        self.assertEqual(mode['runtimeStatus'], 'unverified')

    def test_addon_requires_base_segments_even_if_addon_matches(self):
        (self.tree / 'base.1.ifs').unlink()
        _, v = self.validation()
        mode = next(x for x in v['records'] if x['id'] == 'zhunt')
        statuses = {x['path']: x['status'] for x in mode['fileValidation']['original']}
        self.assertEqual(statuses['addon.ifs'], 'verified')
        self.assertEqual(statuses['base.1.ifs'], 'missing')
        self.assertFalse(mode['declaredDependenciesVerified']['original'])

    def test_corrupt_mismatched_missing_and_unlisted_are_distinct(self):
        (self.tree / 'base.ifs').write_bytes(b'xxxx')
        (self.tree / 'base.1.ifs').write_bytes(b'x')
        (self.tree / 'addon.ifs').unlink()
        (self.tree / 'extra.ifs').write_bytes(b'extra')
        self.inventory['specialModes'][0]['recordedAddons'][0]['dependencies'] = ['unlisted.ifs']
        self.write_content()
        _, v = self.validation()
        mode = next(x for x in v['records'] if x['id'] == 'zhunt')
        statuses = {x['path']: x['status'] for x in mode['fileValidation']['original']}
        self.assertEqual(statuses, {'base.ifs': 'corrupt', 'base.1.ifs': 'mismatched',
                                    'addon.ifs': 'missing', 'unlisted.ifs': 'unlisted'})
        self.assertIn('extra.ifs', v['unlistedFiles']['original'])
        self.assertIn({'path': 'unlisted.ifs', 'reason': 'unlisted_dependency'}, mode['unresolvedDependencies'])

    def test_cycle_and_transitive_dependency_do_not_recurse_forever(self):
        ps = self.inventory['maps'][0]['recordedPackages']
        ps[0]['dependencies'] = ['base.1.ifs']
        ps[1]['dependencies'] = ['base.ifs']
        self.inventory['specialModes'][0]['recordedAddons'][0]['dependencies'] = ['base.ifs']
        self.write_content()
        _, v = self.validation()
        mode = next(x for x in v['records'] if x['id'] == 'zhunt')
        self.assertEqual(len(mode['dependencyEdges']), 3)
        self.assertIn('dependency_cycle', [x['reason'] for x in mode['unresolvedDependencies']])
        self.assertFalse(mode['declaredDependenciesVerified']['original'])

    def test_invalid_dependency_schema_and_duplicates_rejected(self):
        for deps in [['../bad'], ['base.ifs', 'BASE.IFS'], [1], 'base.ifs']:
            self.inventory['maps'][0]['recordedPackages'][0]['dependencies'] = deps
            self.write_content()
            with self.subTest(deps=deps), self.assertRaises(ValueError): r.load_content_inventory(self.content)

    def test_deterministic_projection_despite_record_order(self):
        report = r.reconcile(self.files, {'original': self.tree}, 'manifest')
        first = r.content_validation(report, self.inventory)
        reverse = copy.deepcopy(self.inventory)
        reverse['maps'].reverse()
        reverse['specialModes'].reverse()
        reverse['maps'][0]['recordedPackages'].reverse()
        second = r.content_validation(report, reverse)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))

    def test_unavailable_files_remain_separate_from_missing(self):
        report = r.reconcile(self.files, {'original': None}, 'manifest')
        v = r.content_validation(report, self.inventory)
        self.assertTrue(all(p['status'] == 'unavailable' for row in v['records']
                            for p in row['fileValidation']['original']))

    def test_conflicting_declarations_are_deterministic_and_unresolved(self):
        duplicate = copy.deepcopy(self.inventory['maps'][0]['recordedPackages'][0])
        duplicate['dependencies'] = ['base.1.ifs']
        duplicate['mapId'] = 'mp_fixture'
        self.inventory['maps'][0]['recordedPackages'][0]['dependencies'] = []
        self.inventory['specialModes'][1]['recordedAddons'] = [duplicate]
        report = r.reconcile(self.files, {'original': self.tree}, 'manifest')
        a = r.content_validation(report, self.inventory)
        reverse = copy.deepcopy(self.inventory)
        reverse['specialModes'].reverse()
        b = r.content_validation(report, reverse)
        self.assertEqual(a, b)
        row = next(x for x in a['records'] if x['kind'] == 'map')
        self.assertIn('conflicting_dependency_declarations', [x['reason'] for x in row['unresolvedDependencies']])
        self.assertFalse(row['declaredDependenciesVerified']['original'])
