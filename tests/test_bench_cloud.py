"""The one-command cloud runner: argument assembly, auto-resume and result zipping (no Ollama, no model)."""
import json
import zipfile

from guardml.bench import cloud


class TestCloudRunner:
    def test_tag_is_filename_safe(self):
        assert cloud.default_tag('qwen2.5:14b') == 'live-ollama-qwen2.5-14b'
        assert cloud.default_tag('qwen2.5:14b', smoke=True) == 'live-ollama-qwen2.5-14b-smoke'

    def test_smoke_limits_to_three_scenarios_and_resume_is_added_only_when_asked(self, tmp_path):
        ns = type('NS', (), dict(split='live', configs='c_toolguard', repeat=1, limit=0, smoke=True))()
        args = cloud.build_args(ns, tmp_path, 't', resume=False)
        assert args[args.index('--limit') + 1] == '3' and '--resume' not in args and '--yes' in args
        assert '--resume' in cloud.build_args(ns, tmp_path, 't', resume=True)

    def test_main_picks_up_a_checkpoint_runs_the_benchmark_and_zips_the_results(self, tmp_path, monkeypatch):
        from guardml.bench import run as runmod
        monkeypatch.setattr(cloud, 'ensure_python_deps', lambda: None)
        monkeypatch.setattr(cloud, 'ensure_ollama', lambda model: None)
        (tmp_path / 'live-ollama-m-1.partial.jsonl').write_text('{}\n', encoding='utf-8')
        seen = {}

        def fake_bench(argv):
            seen['argv'] = argv
            (tmp_path / 'live-ollama-m-1.md').write_text('# r', encoding='utf-8')
            (tmp_path / 'live-ollama-m-1.json').write_text(json.dumps({}), encoding='utf-8')
            return 0

        monkeypatch.setattr(runmod, 'main', fake_bench)
        assert cloud.main(['--model', 'm:1', '--out', str(tmp_path)]) == 0
        assert '--resume' in seen['argv'] and seen['argv'][seen['argv'].index('--tag') + 1] == 'live-ollama-m-1'
        with zipfile.ZipFile(tmp_path / 'live-ollama-m-1-results.zip') as z:
            assert sorted(z.namelist()) == ['live-ollama-m-1.json', 'live-ollama-m-1.md']
