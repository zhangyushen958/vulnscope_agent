import io
import json
import zipfile
import pytest
from fastapi.testclient import TestClient
from app.dataset_adapter import build_course_cases, normalize_missing, read_dataset_archive
from app.rag import HistoricalKB
from app.repository import parse_commit_url
from scripts.evaluate_course import evaluate


def course_pair(sha='a'*40, name='CVE-1'):
    base = dict(commit_id=sha, commit_url=f'https://github.com/o/r/commit/{sha}',
                cve=name, cwe=['CWE-119'], file_name='None', project='p',
                func_hash=0, cve_desc='example', commit_message='fixed')
    return [{**base, 'idx':1, 'target':1, 'func':'int g(int *x) { return x[100]; }'},
            {**base, 'idx':2, 'target':0, 'func':'int g(int *x) { return x ? x[0] : 0; }'}]


def zip_data(name, raw):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('dataset/'+name,raw)
    return buf.getvalue()


def test_course_pair_conversion_and_missing():
    cases,audit=build_course_cases(course_pair())
    assert audit.accepted_pairs==1 and audit.rejected_pairs==0
    assert cases[0]['cwe']=='CWE-119' and cases[0]['file_name']==''
    assert normalize_missing('None')==''


def test_inconsistent_pairs_are_not_learned():
    good=course_pair()
    mismatch=course_pair('b'*40, 'CVE-2')
    bad=[good[0],mismatch[1]]
    cases,audit=build_course_cases(good+bad)
    assert len(cases)==1 and audit.rejected_offsets==(3,)


def test_course_import_de_duplicates_and_audits(tmp_path):
    rows=course_pair()+course_pair()
    kb=HistoricalKB(tmp_path/'kb.json')
    assert kb.import_jsonl(('\n'.join(map(json.dumps,rows))).encode())==1
    assert kb.stats()['import_audit']['duplicate_pairs']==1
    assert kb.stats()['cwe_types']==1
    assert HistoricalKB(tmp_path/'kb.json').stats()['case_count']==1


def test_archive_allowlist():
    raw=b'{"idx":2,"func":"something"}\n'
    packed=zip_data('test.jsonl',raw)
    assert read_dataset_archive(packed,'test.jsonl')==raw
    with pytest.raises(ValueError,match='缺少唯一'):
        read_dataset_archive(packed,'knowledge.jsonl')
    with pytest.raises(ValueError):
        read_dataset_archive(packed,'evil.sh')


def test_course_evaluator_positional_partial_and_mismatched_commits():
    truth=[{'idx':1,'target':1,'commit_url':'a'}, {'idx':2,'target':0,'commit_url':'b'},
           {'idx':3,'target':1,'commit_url':'x'}, {'idx':4,'target':0,'commit_url':'y'}]
    assert evaluate(truth,[{'idx':1,'prediction':1},{'idx':2,'prediction':0}])['P-C']==1
    assert evaluate(truth,[{'idx':1,'prediction':1},{'idx':2,'prediction':0}])['evaluated_pairs']==1
    assert evaluate(truth,[{'idx':1,'prediction':0},{'idx':2,'prediction':1}])['P-R']==1


def test_historical_qemu_alias_only():
    spec=parse_commit_url('https://git.qemu.org/?p=qemu.git;a=commit;h='+'e'*40)
    assert (spec.owner,spec.repo,spec.fix_sha)==('qemu','qemu','e'*40)
    with pytest.raises(ValueError):
        parse_commit_url('https://git.qemu.org/?p=other.git;a=commit;h='+'e'*40)


@pytest.fixture
def client(tmp_path):
    from app.config import Settings
    from app.service import DetectionService
    from app.web import create_app
    from tests.test_agent import ScriptedModel, VERDICT
    model = ScriptedModel([('submit_verdict', VERDICT)] * 4)
    return TestClient(create_app(DetectionService(Settings(data_dir=tmp_path), model=model)))


def test_batch_course_zip(client):
    sample=[{'idx':1001,'target':1,'func':'int f(void) { return 1; }'},
            {'idx':1002,'target':0,'func':'int f(void) { return 2; }'}]
    res=client.post('/api/jobs/batch',files={'file':('dataset.zip',zip_data('test.jsonl','\n'.join(json.dumps(x) for x in sample).encode()),'application/zip')})
    assert res.status_code==202 and res.json()['total']==2


def test_model_select_api_and_persistence(client, tmp_path):
    from app.config import Settings
    from app.service import DetectionService
    assert client.get('/api/models').json()['active']['model'] == 'deepseek-v4.1-flash-1017'
    model_info = client.get('/api/models').json()
    assert model_info['provider'] == 'aliyun-bailian'
    assert model_info['models'] == ['deepseek-v4.1-flash-1017', 'deepseek-v4-pro']
    body={'model':'deepseek-v4-pro','thinking':'enabled','max_agent_steps':12}
    res=client.post('/api/models/select',json=body)
    assert res.status_code==200 and res.json()['active']==body
    assert client.get('/api/models').json()['active']==body
    original=client.app.state.service
    reopened=DetectionService(Settings(data_dir=original.settings.data_dir))
    assert reopened.get_profile()==body
    assert client.post('/api/models/select',json={**body,'model':'not-allowed'}).status_code==422
    assert client.post('/api/models/test').status_code==422


def test_deepseek_reasoning_content_preserved(tmp_path):
    import httpx
    from app.config import Settings
    from app.llm import OpenAICompatibleClient
    sent=[]
    def reply(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200,json={'choices':[{'message':{
            'role':'assistant','content':None,'reasoning_content':'private model content from API',
            'tool_calls':[{'id':'id-1','type':'function','function':{'name':'submit_verdict','arguments':'{}'}}]}}]})
    model=OpenAICompatibleClient(Settings(data_dir=tmp_path,llm_api_key='fake',llm_base_url='https://api.deepseek.com'),
                                 transport=httpx.MockTransport(reply),thinking='enabled')
    out=model.complete([{'role':'user','content':'test'}],[])
    assert sent[0]['thinking']=={'type':'enabled'}
    assert sent[0]['tool_choice']=='auto'
    assert out.message['reasoning_content']=='private model content from API'


def test_zip_knowledge_ui_import(client):
    raw='\n'.join(json.dumps(x) for x in course_pair()).encode()
    res=client.post('/api/knowledge/import',files={'file':('dataset.zip',zip_data('knowledge.jsonl',raw),'application/zip')})
    assert res.status_code==200
    assert res.json()['imported_pairs']==1
    assert res.json()['knowledge']['import_audit']['accepted_pairs']==1


def test_lazy_repository_does_not_fetch_until_tool_called(tmp_path):
    from app.service import LazyRepository
    class Provider:
        def __init__(self): self.calls=[]
        def fetch(self, url, target):
            self.calls.append((url,target))
            return tmp_path, 'a'*40
    (tmp_path / 'hello.c').write_text('int helper() { return 3; }\n',encoding='utf8')
    provider=Provider()
    records=[]
    repo=LazyRepository(provider,'https://github.com/o/r/commit/'+'b'*40,1,
                        lambda sha,count:records.append((sha,count)))
    assert provider.calls==[]
    result=repo.search_code('helper')
    assert provider.calls==[('https://github.com/o/r/commit/'+'b'*40,1)]
    assert len(records)==1
    repo.search_code('helper')
    assert len(provider.calls)==1


def test_legacy_flash_model_profile_is_migrated(client):
    from app.model_profile import ModelProfile
    legacy = {"model": "deepseek-flash", "thinking": "disabled", "max_agent_steps": 8}
    profile = ModelProfile.validate(legacy)
    assert profile.model == "deepseek-v4.1-flash-1017"


@pytest.mark.parametrize("selected_model", ["deepseek-v4.1-flash-1017", "deepseek-v4-pro"])
def test_model_test_endpoint_forces_tool_call_in_non_thinking_mode(client, monkeypatch, selected_model):
    import app.llm
    from app.llm import ModelTurn, ToolCall
    captured = {}

    class FakeClient:
        def __init__(self, settings, thinking="disabled"):
            captured["model"] = settings.llm_model
            captured["thinking"] = thinking

        def complete(self, messages, tools, *, tool_choice=None):
            captured["tool_choice"] = tool_choice
            captured["tools"] = [t["function"]["name"] for t in tools]
            call = ToolCall("test-call", "submit_verdict", {})
            return ModelTurn({"role": "assistant", "content": None}, [call], "tool_calls")

    monkeypatch.setattr(app.llm, "OpenAICompatibleClient", FakeClient)
    svc = client.app.state.service
    svc.settings = __import__("dataclasses").replace(svc.settings, llm_api_key="configured-test-key")
    assert client.post("/api/models/select", json={
        "model": selected_model, "thinking": "enabled", "max_agent_steps": 8
    }).status_code == 200
    response = client.post("/api/models/test")
    assert response.status_code == 200
    data = response.json()
    assert data["connected"] is True and data["tool_call_supported"] is True
    assert captured["model"] == selected_model
    assert captured["thinking"] == "disabled"
    assert captured["tool_choice"] == "required"
    assert captured["tools"] == ["submit_verdict"]
