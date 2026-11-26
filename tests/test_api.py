import io
import json
import time
from fastapi.testclient import TestClient
import pytest
from app.config import Settings
from app.service import DetectionService
from app.web import create_app
from tests.test_agent import ScriptedModel, VERDICT, SAMPLE

@pytest.fixture
def client(tmp_path):
    model=ScriptedModel([('submit_verdict',VERDICT)]*10)
    service=DetectionService(Settings(data_dir=tmp_path),model=model)
    return TestClient(create_app(service))


def wait_for(client,job_id):
    for _ in range(100):
        response=client.get(f'/api/jobs/{job_id}')
        if response.json()['status'] in {'completed','failed','partial'}:
            return response.json()
        time.sleep(.03)
    raise AssertionError('job did not complete')


def test_static_ui(client):
    assert client.get('/').status_code==200
    assert '函数漏洞检测' in client.get('/').text
    assert client.get('/static/app.js').status_code==200
    assert 'textContent' in client.get('/static/app.js').text
    assert client.get('/api/health').json()['knowledge']['case_count']==0


def test_single_job_end_to_end_and_export(client):
    resp=client.post('/api/jobs/single',json={'idx':7,'func':SAMPLE})
    assert resp.status_code==202
    job_id=resp.json()['job_id']
    status=wait_for(client,job_id)
    assert status['status']=='completed'
    assert status['rows'][0]['report']['prediction']==0
    payload=client.get(f'/api/jobs/{job_id}/download?format=result')
    assert payload.status_code==200
    assert json.loads(payload.text)=={'idx':7,'prediction':0}
    reports=client.get(f'/api/jobs/{job_id}/download?format=reports').json()
    assert reports['rows'][0]['report']['trace'][0]['kind']=='knowledge'


def test_batch_and_sse(client):
    rows=[{'idx':'1','func':SAMPLE},{'idx':'2','func':'int example(int x) { return x+1; }'}]
    data='\n'.join(json.dumps(r) for r in rows).encode()
    job=client.post('/api/jobs/batch',files={'file':('test.jsonl',data,'application/x-ndjson')}).json()['job_id']
    assert wait_for(client,job)['success']==2
    events=client.get(f'/api/jobs/{job}/events').text
    assert 'event: trace' in events and 'event: finished' in events
    assert len(client.get(f'/api/jobs/{job}/download').text.splitlines())==2


def test_schema_reject_commit_without_target(client):
    r=client.post('/api/jobs/single',json={'idx':1,'func':SAMPLE,'commit_url':'https://github.com/a/b/commit/'+'a'*40})
    assert r.status_code==422


def test_knowledge_upload(client):
    row={'vulnerable_func':'int f(char*p){return p[0];}', 'fixed_func':'int f(char*p){return p?p[0]:0;}', 'cwe':'CWE-DEMO'}
    raw=json.dumps(row).encode()
    r=client.post('/api/knowledge/import',files={'file':('history.jsonl',raw,'application/x-ndjson')})
    assert r.status_code==200
    assert r.json()['imported_pairs']==1
    assert client.get('/api/health').json()['knowledge']['cwe_types']==1


def test_reject_duplicate_idx(client):
    data='\n'.join(json.dumps({'idx':1,'func':SAMPLE}) for _ in range(2)).encode()
    resp=client.post('/api/jobs/batch',files={'file':('test.jsonl',data)})
    assert resp.status_code==422


def test_missing_llm_fails_no_fabricated_prediction(tmp_path):
    from app.llm import OpenAICompatibleClient
    settings=Settings(data_dir=tmp_path,llm_api_key='',llm_base_url='https://api.openai.com/v1')
    service=DetectionService(settings)
    client=TestClient(create_app(service))
    job=client.post('/api/jobs/single',json={'idx':1,'func':SAMPLE}).json()['job_id']
    status=wait_for(client,job)
    assert status['status']=='failed'
    assert status['rows'][0]['report'] is None
    assert client.get(f'/api/jobs/{job}/download?format=result').status_code==409


def test_partial_batch_refuses_incomplete_result(tmp_path):
    class FailsSecond:
        def __init__(self):self.n=0
        def complete(self,messages,tools):
            from app.llm import ModelTurn, ToolCall
            self.n+=1
            if self.n==2:
                raise RuntimeError('model unavailable')
            call=ToolCall('x','submit_verdict',VERDICT)
            return ModelTurn(message={'role':'assistant','content':None,'tool_calls':[{'id':'x','type':'function','function':{'name':'submit_verdict','arguments':'{}'}}]},calls=[call])
    svc=DetectionService(Settings(data_dir=tmp_path),model=FailsSecond())
    client=TestClient(create_app(svc))
    raw='\n'.join(json.dumps({'idx':i,'func':SAMPLE}) for i in (1,2)).encode()
    jid=client.post('/api/jobs/batch',files={'file':('cases.jsonl',raw)}).json()['job_id']
    job=wait_for(client,jid)
    assert (job['success'],job['failures'],job['status'])==(1,1,'partial')
    assert client.get(f'/api/jobs/{jid}/download?format=result').status_code==409
    assert len(client.get(f'/api/jobs/{jid}/download?format=reports').json()['rows'])==2
