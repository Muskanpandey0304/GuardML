"""The CI regression gate must actually fail when the guard gets worse."""
import copy
import json

import pytest

from guardml.bench.check_regression import BASELINE, compare, main


@pytest.fixture(scope='module')
def baseline():
    return json.loads(BASELINE.read_text(encoding='utf-8'))


def worse(base, cfg, section, key, value):
    new = copy.deepcopy(base)
    new['summary'][cfg][section][key] = value
    return new


class TestGate:
    def test_committed_baseline_has_the_configs_ci_compares(self, baseline):
        assert {'a_no_guard', 'c_toolguard', 'd_provenance'} <= set(baseline['summary'])

    def test_identical_run_passes(self, baseline):
        assert compare(copy.deepcopy(baseline), baseline) == []

    def test_higher_attack_success_fails(self, baseline):
        cur = baseline['summary']['d_provenance']['attack']['asr_unattended']
        problems = compare(worse(baseline, 'd_provenance', 'attack', 'asr_unattended', cur + 0.05), baseline)
        assert problems and 'd_provenance' in problems[0] and 'attack success' in problems[0]

    def test_higher_rubber_stamp_success_fails(self, baseline):
        cur = baseline['summary']['c_toolguard']['attack']['asr_rubber_stamp']
        assert compare(worse(baseline, 'c_toolguard', 'attack', 'asr_rubber_stamp', cur + 0.1), baseline)

    def test_lower_benign_completion_fails_and_names_the_tasks(self, baseline):
        new = worse(baseline, 'c_toolguard', 'benign', 'utility', 0.5)
        new['summary']['c_toolguard']['benign']['failed_tasks'] = ['ben-02-rollback']
        problems = compare(new, baseline)
        assert problems and 'ben-02-rollback' in problems[0]

    def test_more_false_positives_fail(self, baseline):
        assert compare(worse(baseline, 'd_provenance', 'benign', 'false_positive_rate', 0.2), baseline)

    def test_errored_runs_fail(self, baseline):
        new = copy.deepcopy(baseline)
        new['summary']['c_toolguard']['errors'] = ['ben-01: boom']
        assert any('errored' in p for p in compare(new, baseline))

    def test_better_results_pass(self, baseline):
        assert compare(worse(baseline, 'c_toolguard', 'attack', 'asr_unattended', 0.0), baseline) == []

    def test_no_guard_baseline_is_ignored(self, baseline):
        assert compare(worse(baseline, 'a_no_guard', 'attack', 'asr_unattended', 0.0), baseline) == []

    def test_changed_scenario_counts_ask_for_a_new_baseline(self, baseline):
        new = worse(baseline, 'c_toolguard', 'attack', 'n', baseline['summary']['c_toolguard']['attack']['n'] + 1)
        problems = compare(new, baseline)
        assert problems and 'regenerate' in problems[0]

    def test_missing_config_fails(self, baseline):
        new = copy.deepcopy(baseline)
        del new['summary']['d_provenance']
        assert any('missing' in p for p in compare(new, baseline))

    def test_cli_exit_codes(self, baseline, tmp_path, capsys):
        ok = tmp_path / 'ok.json'
        ok.write_text(json.dumps(baseline), encoding='utf-8')
        assert main([str(ok)]) == 0
        bad = tmp_path / 'bad.json'
        bad.write_text(json.dumps(worse(baseline, 'd_provenance', 'attack', 'asr_unattended', 1.0)), encoding='utf-8')
        assert main([str(bad)]) == 1
        assert 'REGRESSION' in capsys.readouterr().out
        assert main([]) == 2
