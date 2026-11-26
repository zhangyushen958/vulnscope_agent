"""V3: local dataset import/batch, durable artifacts, course evaluation, isolation."""
import json
import time
from pathlib import Path
from fastapi.testclient import TestClient
from app.config import Settings
from app.service import DetectionService
from app.web import create_app
from tests.test_agent import ScriptedModel, VERDICT, SAMPLE


def fixture_app(tmp_path):
    data = tmp_path / 'dataset'
    data.mkdir()
    result = tmp_path / 'result'
    settings = Settings(data_dir=tmp_path / 'runtime', dataset_dir=data, result_dir=result)
    service = DetectionService(settings, model=ScriptedModel([('submit_verdict',VERDICT)] * 12))
    return TestClient(create_app(service)), data, result


def completed(client, job_id):
    for _ in range(100):
        r = client.get(f'/api/jobs/{job_id}').json()
        if r['status'] in ('completed','partial','failed'):
            return r
        time.sleep(.02)
    raise AssertionError('job timed out')


def test_local_dataset_workflow_and_saved_score(tmp_path):
    client, data, result = fixture_app(tmp_path)
    rows = [
        {'idx':10, 'target':1, 'func':SAMPLE},
        {'idx':11, 'target':0, 'func':SAMPLE},
        {'idx':12, 'target':1, 'func':SAMPLE},
        {'idx':13, 'target':0, 'func':SAMPLE}
    ]
    (data/'test.jsonl').write_text('\n'.join(json.dumps(r) for r in rows), encoding='utf-8')
    resp = client.post('/api/jobs/batch-local')
    assert resp.status_code==202, resp.text
    job_id=resp.json()['job_id']
    assert completed(client, job_id)['success']==4
    out=result/job_id
    assert (out/'result.jsonl').exists()
    preds=[json.loads(x) for x in (out/'result.jsonl').read_text().splitlines()]
    assert [x['idx'] for x in preds]==[10,11,12,13]
    score=client.get(f'/api/jobs/{job_id}/score')
    assert score.status_code==200,score.text
    assert score.json()['P-B']==2
    assert score.json()['evaluated_pairs']==2
    assert score.json()['complete'] is True
    assert (out/'score.json').exists()
    assert (out/'reports.json').exists()
    assert client.get('/api/results').json()['jobs'][0]['id']==job_id


def test_local_knowledge_import(tmp_path):
    client, data, _=fixture_app(tmp_path)
    raw={'vulnerable_func':'int demo(char*p){return p[0];}', 'fixed_func':'int demo(char*p){return p?p[0]:0;}', 'cwe':'CWE-1'}
    (data/'knowledge.jsonl').write_text(json.dumps(raw),encoding='utf-8')
    assert client.get('/api/health').json()['dataset_files']['knowledge.jsonl']
    res=client.post('/api/knowledge/import-local')
    assert res.status_code==200,res.text
    assert res.json()['imported_pairs']==1
    assert client.get('/api/health').json()['knowledge']['case_count']==1


def test_missing_files_not_fallback_to_remote(tmp_path):
    client, _, _=fixture_app(tmp_path)
    assert client.post('/api/jobs/batch-local').status_code==422
    assert client.post('/api/knowledge/import-local').status_code==422


def test_symlink_source_blocked(tmp_path):
    client, data, _=fixture_app(tmp_path)
    outside=tmp_path/'outside.jsonl';outside.write_text('{}')
    (data/'test.jsonl').symlink_to(outside)
    assert client.post('/api/jobs/batch-local').status_code==422


def test_unfinished_job_cannot_be_scored(tmp_path):
    client, data, _=fixture_app(tmp_path)
    job_id=client.app.state.service.store.new_job('batch',2)
    assert client.get(f'/api/jobs/{job_id}/score').status_code==409


def test_single_job_not_course_scored(tmp_path):
    client, data, _=fixture_app(tmp_path)
    jid=client.post('/api/jobs/single',json={'idx':'man','func':SAMPLE}).json()['job_id']
    completed(client,jid)
    assert client.get(f'/api/jobs/{jid}/score').status_code==422


def test_unauthorized_data_not_reported_in_score(tmp_path):
    client, data, _=fixture_app(tmp_path)
    (data/'test.jsonl').write_text('\n'.join(json.dumps(x) for x in [
        {'idx':1,'target':1,'func':SAMPLE},{'idx':2,'target':0,'func':SAMPLE}]),encoding='utf-8')
    upload='\n'.join(json.dumps({'idx':i,'func':SAMPLE}) for i in [77,78]).encode()
    jid=client.post('/api/jobs/batch',files={'file':('test.jsonl',upload)}).json()['job_id']
    completed(client,jid)
    assert client.get(f'/api/jobs/{jid}/score').status_code==422


def test_scoring_view_present(tmp_path):
    client,_,_=fixture_app(tmp_path)
    html=client.get('/').text
    assert 'id="tab-scoring"' in html and 'id="runLocalKnowledge"' in html and 'id="runLocalBatch"' in html
    script=client.get('/static/app.js').text
    assert 'showScore' in script and 'grade_is_provisional' not in html


def test_partial_output_never_named_result(tmp_path):
    class Fail:
        def complete(self,messages,tools):
            raise RuntimeError('model failed')
    data=tmp_path/'dataset';data.mkdir()
    service=DetectionService(Settings(data_dir=tmp_path/'runtime',dataset_dir=data,result_dir=tmp_path/'result'),model=Fail())
    client=TestClient(create_app(service))
    jid=client.post('/api/jobs/single',json={'idx':1,'func':SAMPLE}).json()['job_id']
    assert completed(client,jid)['status']=='failed'
    folder=tmp_path/'result'/jid
    assert not (folder/'result.jsonl').exists()
    assert (folder/'partial_predictions.jsonl').exists()


def test_score_provisional_for_partial():
    from app.course_io import grade_result
    truth=[{'idx':1,'target':1},{'idx':2,'target':0},{'idx':3,'target':1},{'idx':4,'target':0}]
    result=grade_result(truth,[{'idx':1,'prediction':1},{'idx':2,'prediction':0}])
    assert result['P-C']==1 and result['complete'] is False and result['grade_is_provisional'] is True

def test_score_uses_exact_submission_snapshot_after_local_dataset_changes(tmp_path):
    client,data,result=fixture_app(tmp_path)
    original=[{'idx':1,'target':1,'func':SAMPLE},{'idx':2,'target':0,'func':SAMPLE}]
    path=data/'test.jsonl'
    path.write_text('\n'.join(json.dumps(x) for x in original), encoding='utf-8')
    jid=client.post('/api/jobs/batch-local').json()['job_id']
    completed(client,jid)

    # Replacing test.jsonl after submission must not silently change the
    # samples or pair relationships used to score this already-completed job.
    changed=[dict(x) for x in original]
    changed[0]['func']='int modified(int x){return x*2;}'
    path.write_text('\n'.join(json.dumps(x) for x in changed), encoding='utf-8')
    snapshot=result/jid/'submitted_dataset.jsonl'
    assert snapshot.exists()
    assert json.loads(snapshot.read_text(encoding='utf-8').splitlines()[0])['func']==SAMPLE

    res=client.get(f'/api/jobs/{jid}/score')
    assert res.status_code==200, res.text
    assert res.json()['evaluated_pairs']==1
    assert res.json()['complete'] is True


def test_uploaded_demo_subset_scores_against_uploaded_content_not_local_test(tmp_path):
    client,data,result=fixture_app(tmp_path)
    # The local official test set is intentionally a different full dataset.
    local=[{'idx':101,'target':1,'func':SAMPLE},{'idx':102,'target':0,'func':SAMPLE}]
    (data/'test.jsonl').write_text('\n'.join(json.dumps(x) for x in local), encoding='utf-8')

    demo=[{'idx':201,'target':1,'func':SAMPLE},{'idx':202,'target':0,'func':SAMPLE}]
    raw=('\n'.join(json.dumps(x) for x in demo)+'\n').encode()
    submitted=client.post('/api/jobs/batch', files={'file':('demo.jsonl',raw,'application/x-ndjson')})
    assert submitted.status_code==202, submitted.text
    jid=submitted.json()['job_id']
    assert completed(client,jid)['success']==2

    snapshot=result/jid/'submitted_dataset.jsonl'
    saved=[json.loads(line) for line in snapshot.read_text(encoding='utf-8').splitlines()]
    assert [row['idx'] for row in saved]==[201,202]
    score=client.get(f'/api/jobs/{jid}/score')
    assert score.status_code==200, score.text
    assert score.json()['pairs']==1
    assert score.json()['evaluated_pairs']==1


def test_scoring_rejects_tampered_submission_snapshot(tmp_path):
    client,data,result=fixture_app(tmp_path)
    rows=[{'idx':301,'target':1,'func':SAMPLE},{'idx':302,'target':0,'func':SAMPLE}]
    raw=('\n'.join(json.dumps(x) for x in rows)+'\n').encode()
    submitted=client.post('/api/jobs/batch',files={'file':('demo.jsonl',raw)})
    jid=submitted.json()['job_id']
    completed(client,jid)
    snapshot=result/jid/'submitted_dataset.jsonl'
    changed=[dict(x) for x in rows]
    changed[0]['func']='int tampered(int x){return x-1;}'
    snapshot.write_text('\n'.join(json.dumps(x) for x in changed)+'\n', encoding='utf-8')
    res=client.get(f'/api/jobs/{jid}/score')
    assert res.status_code==422
    assert '摘要不一致' in res.json()['detail']


def test_course_scoring_four_categories():
    from app.course_io import grade_result
    rows=[];preds=[]
    for j,(v,f) in enumerate([(1,0),(1,1),(0,0),(0,1)]):
        a=2*j;b=a+1
        rows.extend([{'idx':a,'target':1},{'idx':b,'target':0}])
        preds.extend([{'idx':a,'prediction':v},{'idx':b,'prediction':f}])
    score=grade_result(rows,preds)
    assert [score[k] for k in ('P-C','P-V','P-B','P-R')]==[1,1,1,1]
    assert score['penalty'] is True
