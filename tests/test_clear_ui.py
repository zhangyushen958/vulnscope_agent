"""Safe reset lifecycle: keep datasets and config, remove completed jobs/trace files."""
import json
import time
import threading
from fastapi.testclient import TestClient
from app.config import Settings
from app.service import DetectionService
from app.web import create_app
from tests.test_agent import ScriptedModel, VERDICT, SAMPLE


def fixture_service(tmp_path):
    settings = Settings(data_dir=tmp_path / 'runtime', result_dir=tmp_path / 'result', dataset_dir=tmp_path / 'dataset')
    settings.dataset_dir.mkdir()
    (settings.dataset_dir / 'test.jsonl').write_text('{}\n')
    service = DetectionService(settings, model=ScriptedModel([('submit_verdict', VERDICT)] * 6))
    return TestClient(create_app(service)), service


def finished(client, jid):
    for _ in range(150):
        job = client.get(f'/api/jobs/{jid}').json()
        if job['status'] in {'completed', 'failed', 'partial'}:
            return job
        time.sleep(.02)
    raise AssertionError('job unfinished')


def submit(client, idx):
    r = client.post('/api/jobs/single', json={'idx':idx, 'func':SAMPLE})
    assert r.status_code == 202
    jid = r.json()['job_id']
    finished(client, jid)
    return jid


def test_clear_one_and_resubmit_without_restart(tmp_path):
    client, service = fixture_service(tmp_path)
    a, b = submit(client, 1), submit(client, 2)
    out = service.settings.result_dir
    assert (out / a / 'events.jsonl').exists()
    assert client.post('/api/results/clear', json={'job_id':a}).status_code == 422
    assert client.post('/api/results/clear', json={'confirm':'CLEAR_RESULTS', 'job_id':'../../wrong'}).status_code == 422
    r = client.post('/api/results/clear', json={'confirm':'CLEAR_RESULTS','job_id':a})
    assert r.status_code == 200 and r.json()['deleted_jobs'] == 1
    assert client.get(f'/api/jobs/{a}').status_code == 404
    assert not (out / a).exists()
    assert (out / b).exists()
    assert client.get(f'/api/jobs/{b}').status_code == 200
    assert client.post('/api/results/clear', json={'confirm':'CLEAR_RESULTS','job_id':a}).status_code == 404
    c = submit(client, 3)
    assert (out / c / 'reports.json').exists()
    assert (service.settings.dataset_dir / 'test.jsonl').exists()


def test_clear_all_preserves_profile_and_knowledge(tmp_path):
    client, svc = fixture_service(tmp_path)
    case={'vulnerable_func':'int f(char*p){return p[0];}', 'fixed_func':'int f(char*p){return p?p[0]:0;}', 'cwe':'CWE-TEST'}
    assert client.post('/api/knowledge/import', files={'file':('knowledge.jsonl', json.dumps(case).encode())}).status_code == 200
    original = client.get('/api/models').json()['active']
    ids = [submit(client, i) for i in (1,2)]
    r = client.post('/api/results/clear',json={'confirm':'CLEAR_RESULTS'})
    assert r.status_code == 200 and r.json()['deleted_jobs'] == 2
    assert client.get('/api/results').json()['jobs'] == []
    assert client.get('/api/health').json()['knowledge']['case_count'] == 1
    assert client.get('/api/models').json()['active'] == original
    assert all(not (svc.settings.result_dir / j).exists() for j in ids)
    assert (svc.settings.dataset_dir / 'test.jsonl').exists()
    assert submit(client, 5)


def test_clear_knowledge_preserves_dataset_and_is_repeatable(tmp_path):
    client, svc = fixture_service(tmp_path)
    data={'vulnerable_func':'int f(char*p){return p[0];}', 'fixed_func':'int f(char*p){return p?p[0]:0;}', 'cwe':'CWE-TEST'}
    raw=json.dumps(data).encode()
    client.post('/api/knowledge/import', files={'file':('knowledge.jsonl', raw)})
    assert client.post('/api/knowledge/clear', json={}).status_code == 422
    r = client.post('/api/knowledge/clear',json={'confirm':'CLEAR_KNOWLEDGE'})
    assert r.status_code == 200 and r.json()['deleted_cases'] == 1
    assert client.get('/api/health').json()['knowledge']['case_count'] == 0
    assert not (svc.settings.data_dir / 'historical_cases.json').exists()
    assert (svc.settings.dataset_dir / 'test.jsonl').exists()
    assert client.post('/api/knowledge/clear',json={'confirm':'CLEAR_KNOWLEDGE'}).json()['deleted_cases'] == 0
    assert client.post('/api/knowledge/import', files={'file':('knowledge.jsonl', raw)}).status_code == 200


def test_active_task_blocks_clear(tmp_path):
    client, svc = fixture_service(tmp_path)
    jid = svc.store.new_job('batch', 1)
    assert client.post('/api/results/clear',json={'confirm':'CLEAR_RESULTS'}).status_code == 409
    assert client.post('/api/knowledge/clear',json={'confirm':'CLEAR_KNOWLEDGE'}).status_code == 409
    svc.store.set_status(jid,'failed')
    assert client.post('/api/results/clear',json={'confirm':'CLEAR_RESULTS'}).status_code == 200


def test_frontend_reset_controls_present():
    from pathlib import Path
    base=Path(__file__).resolve().parents[1] / 'app' / 'static'
    html=(base/'index.html').read_text()
    script=(base/'app.js').read_text()
    for id_ in ('clearKnowledge','clearAllResults','deleteScoreJob'):
        assert f'id="{id_}"' in html
        assert f"$('{id_}').addEventListener" in script
    assert 'window.confirm' in script
