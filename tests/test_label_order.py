"""Synthetic issue-3 readiness checks; never query a model or use real records."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from label_order import analyze, build_manifest, digest, load_design, paired_statistics, render_pair, validate_manifest
from fesa_prompts import load_policy


def synthetic_inputs():
    config, _, _ = load_policy()
    datasets = {}
    for domain in ('phishing', 'malware'):
        names = config['datasets'][domain]['included']
        def features(index):
            return {name: index if i == 0 else 0 for i, name in enumerate(names)}
        datasets[domain] = {
            'split_id': 'synthetic-split-v1',
            'queries': [{'query_id': f'synthetic-{domain}-query-{i:03d}', 'label': i % 2, 'features': features(i)} for i in range(200)],
            'demonstrations': [{'demo_id': f'synthetic-{domain}-demo-{i:02d}', 'label': i % 2, 'features': features(1000 + i)} for i in range(10)],
        }
    metadata = {
        'run_id': 'synthetic-issue-3', 'serving_session_id': 'synthetic-session',
        'model_id': 'synthetic/model', 'model_revision': 'synthetic-revision',
        'tokenizer_revision': 'synthetic-tokenizer', 'code_revision': 'synthetic-not-a-commit',
        'decoding': {'temperature': 0.0, 'max_tokens': 32},
    }
    return datasets, metadata


class LabelOrder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.datasets, cls.metadata = synthetic_inputs()
        cls.manifest = build_manifest(cls.datasets, cls.metadata, evidence_class='synthetic')
        cls.fingerprint = digest(cls.manifest)
        # A predicts all malicious, B all benign: a complete reversal with identical accuracy.
        cls.rows = [dict(r, status='valid', attempt_count=1, prediction=1 if r['label_order'] == 'A' else 0) for r in cls.manifest['requests']]

    def run_analysis(self, rows=None, manifest=None, fingerprint=None):
        return analyze(manifest if manifest is not None else self.manifest,
                       rows if rows is not None else self.rows,
                       registered_manifest_sha256=fingerprint or self.fingerprint)

    def test_full_reversal_is_visible_despite_unchanged_accuracy(self):
        result = self.run_analysis()
        self.assertEqual(result['evidence_class'], 'synthetic')
        self.assertIn('SYNTHETIC', result['disclaimer'])
        self.assertEqual((result['request_count'], result['distinct_query_count']), (2400, 400))
        self.assertEqual(len(result['cells']), 12)
        for cell in result['cells']:
            self.assertEqual(cell['accuracy'], 0.5)
        for pair in result['label_order_comparisons']:
            self.assertEqual(pair['transitions'], {'00': 0, '01': 0, '10': 200, '11': 0})
            self.assertEqual(pair['flips'], 200)
            self.assertEqual(pair['flip_rate'], 1.0)
            self.assertEqual(pair['accuracy_p_holm'], 1.0)
            self.assertEqual(pair['accuracy_delta_right_minus_left'], 0.0)
            self.assertEqual(pair['malicious_rate_delta_right_minus_left'], -1.0)
            self.assertTrue(pair['prediction_change_observed'])
            self.assertTrue(pair['directional_reject_at_alpha'])
        serialized = json.dumps(result)
        self.assertNotIn('synthetic-phishing-query', serialized)
        self.assertNotIn('execution_sha256', serialized)
        self.assertNotIn('prompt_sha256', serialized)
        self.assertNotIn('synthetic-session', serialized)
        self.assertEqual(result['model']['model_id'], 'synthetic/model')

    def test_symmetric_flips_are_not_called_invariance(self):
        pair = paired_statistics([0, 0, 1, 1], [0, 1, 0, 1], [1, 0, 1, 0])
        self.assertEqual(pair['flips'], 4)
        self.assertEqual(pair['directional_p_raw'], 1.0)
        self.assertEqual(pair['accuracy_p_raw'], 1.0)
        self.assertTrue(pair['prediction_change_observed'])
        self.assertEqual(pair['malicious_rate_delta_right_minus_left'], 0.0)

    def test_accuracy_and_directional_changes_are_separate(self):
        pair = paired_statistics([0, 1, 0, 1], [1, 0, 0, 1], [0, 1, 0, 1])
        self.assertEqual(pair['correctness'], {'both_correct': 2, 'left_only_correct': 0, 'right_only_correct': 2, 'both_wrong': 0})
        self.assertEqual(pair['accuracy_delta_right_minus_left'], 0.5)
        self.assertEqual(pair['accuracy_p_raw'], 0.5)
        self.assertEqual(pair['directional_p_raw'], 1.0)
        no_flips = paired_statistics([0, 1], [0, 1], [0, 1])
        self.assertEqual(no_flips['accuracy_p_raw'], 1.0)
        self.assertEqual(no_flips['directional_p_raw'], 1.0)
        self.assertFalse(no_flips['prediction_change_observed'])

    def test_exact_tests_and_fixed_multiplicity_families(self):
        rows = [dict(r, prediction=r['gold_label'] if r['label_order'] == 'A' else 1 - r['gold_label']) for r in self.rows]
        result = self.run_analysis(rows)
        self.assertEqual(len(result['label_order_comparisons']), 6)
        self.assertEqual(len(result['count_accuracy_comparisons']), 12)
        raw = 2 / 2**200
        for pair in result['label_order_comparisons']:
            self.assertAlmostEqual(pair['accuracy_p_raw'] / raw, 1.0)
            self.assertAlmostEqual(pair['accuracy_p_holm'] / raw, 6.0)
            self.assertTrue(pair['accuracy_reject_at_alpha'])
            self.assertEqual(pair['directional_p_holm'], 1.0)
        self.assertTrue(all(p['accuracy_p_holm'] == 1.0 for p in result['count_accuracy_comparisons']))

    def test_schedule_is_balanced_complete_and_deterministic(self):
        plan = load_design()
        self.assertEqual(plan['request_budget'], 2400)
        self.assertEqual(plan['retry_budget'], 0)
        requests = self.manifest['requests']
        self.assertEqual(len({(r['dataset'], r['demonstration_count'], r['label_order'], r['query_id']) for r in requests}), 2400)
        first = Counter()
        for offset in range(0, 2400, 40):
            block = requests[offset:offset + 40]
            a, b = block[:20], block[20:]
            self.assertEqual([r['query_id'] for r in a], [r['query_id'] for r in b])
            self.assertNotEqual(a[0]['label_order'], b[0]['label_order'])
            self.assertEqual(len({(r['dataset'], r['demonstration_count'], r['block_id']) for r in block}), 1)
            first[a[0]['dataset'], a[0]['demonstration_count'], a[0]['label_order']] += 1
        self.assertEqual(len(first), 12)
        self.assertEqual(set(first.values()), {5})
        validate_manifest(self.manifest)
        self.assertEqual(self.run_analysis(list(reversed(self.rows))), self.run_analysis())

    def test_rejects_incomplete_extra_duplicate_failed_and_unparseable_rows(self):
        cases = [self.rows[:-1], self.rows + [self.rows[0]]]
        duplicate = copy.deepcopy(self.rows); duplicate[-1] = duplicate[0]; cases.append(duplicate)
        for status, prediction in [('parse_failure', None), ('context_overflow', None), ('truncated', None), ('valid', True), ('valid', '1')]:
            rows = copy.deepcopy(self.rows); rows[0].update(status=status, prediction=prediction); cases.append(rows)
        retried = copy.deepcopy(self.rows); retried[0]['attempt_count'] = 2; cases.append(retried)
        for rows in cases:
            with self.subTest(length=len(rows)), self.assertRaises(ValueError):
                self.run_analysis(rows)

    def test_rejects_response_metadata_and_query_mismatch(self):
        for field, value in [('execution_sha256', '0' * 64), ('prompt_sha256', '0' * 64), ('query_id', 'unexpected-query'), ('gold_label', 1 - self.rows[0]['gold_label']), ('demonstration_count', True), ('block_id', False)]:
            rows = copy.deepcopy(self.rows); rows[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_analysis(rows)

    def test_registered_manifest_is_required_and_cannot_shrink(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['datasets']['phishing']['queries'].pop()
        with self.assertRaisesRegex(ValueError, 'registered digest'):
            self.run_analysis(manifest=manifest)
        with self.assertRaisesRegex(ValueError, 'query count'):
            self.run_analysis(manifest=manifest, fingerprint=digest(manifest))
        manifest = copy.deepcopy(self.manifest)
        manifest['requests'].reverse()
        with self.assertRaisesRegex(ValueError, 'schedule'):
            self.run_analysis(manifest=manifest, fingerprint=digest(manifest))
        manifest = copy.deepcopy(self.manifest)
        manifest['metadata']['serving_session_id'] = 'other-session'
        with self.assertRaisesRegex(ValueError, 'execution metadata'):
            self.run_analysis(manifest=manifest, fingerprint=digest(manifest))

    def test_prompt_pairs_preserve_demonstrations_and_only_change_clause(self):
        for domain in ('phishing', 'malware'):
            for count in (0, 4, 10):
                a, b = render_pair(domain, self.datasets[domain]['queries'][0], self.datasets[domain]['demonstrations'][:count])
                self.assertEqual(a['demonstration_labels'], [i % 2 for i in range(count)])
                config, _, _ = load_policy(); clauses = config['datasets'][domain]
                self.assertEqual(a['prompt'].replace(clauses['label_order_a'], clauses['label_order_b']), b['prompt'])
        manifest = copy.deepcopy(self.manifest)
        manifest['datasets']['malware']['demonstrations'][0]['label'] = 1
        with self.assertRaisesRegex(ValueError, 'balanced'):
            self.run_analysis(manifest=manifest, fingerprint=digest(manifest))

    def test_rejects_query_demo_overlap_and_duplicate_projection(self):
        inputs = copy.deepcopy(self.datasets)
        inputs['phishing']['queries'][0]['features'] = inputs['phishing']['demonstrations'][0]['features']
        with self.assertRaisesRegex(ValueError, 'projected vector'):
            build_manifest(inputs, self.metadata, evidence_class='synthetic')
        manifest = copy.deepcopy(self.manifest)
        manifest['datasets']['phishing']['queries'][0]['query_id'] = manifest['datasets']['phishing']['demonstrations'][0]['demo_id']
        with self.assertRaisesRegex(ValueError, 'overlap'):
            self.run_analysis(manifest=manifest, fingerprint=digest(manifest))

    def test_cli_emits_only_aggregates_and_rejects_bad_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); manifest = root / 'manifest.json'; rows = root / 'predictions.jsonl'
            manifest.write_text(json.dumps(self.manifest)); rows.write_text('\n'.join(json.dumps(r) for r in self.rows))
            cmd = [sys.executable, str(ROOT / 'scripts/analyze_label_order.py'), '--manifest', str(manifest), '--registered-manifest-sha256', self.fingerprint, '--predictions', str(rows)]
            result = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), self.run_analysis())
            rows.write_text(json.dumps(self.rows[0]) + '\n')
            failed = subprocess.run(cmd, text=True, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertEqual(failed.stdout, '')
            self.assertNotIn(str(rows), failed.stderr)


if __name__ == '__main__':
    unittest.main()
