import json
import httpx
import pytest
from app.config import Settings
from app.llm import OpenAICompatibleClient
from app.agent import TOOLS_FINISH


def settings(tmp_path, **kwargs):
    return Settings(data_dir=tmp_path, llm_api_key='token-do-not-log', **kwargs)


def test_real_tool_call_wire_contract(tmp_path):
    requests=[]
    def handler(req):
        requests.append(req)
        return httpx.Response(200,json={'choices':[{'message':{'role':'assistant','content':None,'tool_calls':[
            {'id':'t-1','type':'function','function':{'name':'submit_verdict','arguments':'{"prediction": 0, "reason": "测试逻辑成立的详细理由", "confidence": 0.6, "evidence": ["source"]}'}}
        ]}}]})
    llm=OpenAICompatibleClient(settings(tmp_path),transport=httpx.MockTransport(handler))
    messages=[{'role':'system','content':'Only test'}]
    result=llm.complete(messages,[TOOLS_FINISH])
    assert result.calls[0].name=='submit_verdict'
    assert result.calls[0].arguments['prediction']==0
    assert requests[0].url.path=='/compatible-mode/v1/chat/completions'
    assert requests[0].headers['authorization']=='Bearer token-do-not-log'
    body=json.loads(requests[0].content)
    assert body['tool_choice']=='required' and 'temperature' not in body
    assert all('search' not in x['function']['name'] for x in body['tools'])


def test_http_model_failure_has_clean_error(tmp_path):
    llm=OpenAICompatibleClient(settings(tmp_path),transport=httpx.MockTransport(lambda req:httpx.Response(401,text='secret error body')))
    with pytest.raises(RuntimeError,match='HTTP 401') as exc:
        llm.complete([], [TOOLS_FINISH])
    assert 'secret error body' not in str(exc.value)


def test_malformed_function_arguments_rejected(tmp_path):
    payload={'choices':[{'message':{'tool_calls':[{'id':'bad','function':{'name':'submit_verdict','arguments':'{broken'}}]}}]}
    llm=OpenAICompatibleClient(settings(tmp_path),transport=httpx.MockTransport(lambda req:httpx.Response(200,json=payload)))
    with pytest.raises(RuntimeError,match='function/tool_calls'):
        llm.complete([], [TOOLS_FINISH])


def test_missing_key_does_not_attempt_external_call(tmp_path):
    llm=OpenAICompatibleClient(Settings(data_dir=tmp_path,llm_api_key=''),transport=httpx.MockTransport(lambda req:pytest.fail('called network')))
    with pytest.raises(RuntimeError,match='未配置'):
        llm.complete([], [TOOLS_FINISH])


@pytest.mark.parametrize('url',['http://example.com/v1','file:///tmp/api','https://user:pw@api.example.com/v1'])
def test_insecure_model_endpoint_rejected(tmp_path,url):
    with pytest.raises(ValueError):
        OpenAICompatibleClient(settings(tmp_path,llm_base_url=url))


def test_local_openai_compatible_no_api_key(tmp_path):
    payload={'choices':[{'message':{'tool_calls':[{'id':'r1','function':{'name':'submit_verdict','arguments':'{}'}}]}}]}
    s=Settings(data_dir=tmp_path,llm_api_key='',llm_base_url='http://localhost:12345/v1')
    c=OpenAICompatibleClient(s,transport=httpx.MockTransport(lambda req:httpx.Response(200,json=payload)))
    assert c.complete([], [TOOLS_FINISH]).calls[0].name=='submit_verdict'


def test_bailian_chat_completions_uses_enable_thinking_and_selected_model(tmp_path):
    requests = []
    def handler(req):
        requests.append(req)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    base_url = "https://workspace-id.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
    for model_name, thinking in (("deepseek-v4.1-flash-1017", "disabled"), ("deepseek-v4-pro", "enabled")):
        cfg = settings(tmp_path, llm_base_url=base_url, llm_model=model_name)
        OpenAICompatibleClient(cfg, transport=httpx.MockTransport(handler), thinking=thinking).complete([], [])

    assert requests[0].url.host == "workspace-id.cn-beijing.maas.aliyuncs.com"
    assert requests[0].url.path == "/compatible-mode/v1/chat/completions"
    first, second = [json.loads(req.content) for req in requests]
    assert first["model"] == "deepseek-v4.1-flash-1017"
    assert first["enable_thinking"] is False
    assert "thinking" not in first
    assert second["model"] == "deepseek-v4-pro"
    assert second["enable_thinking"] is True
    assert "thinking" not in second
    # A tools request in non-thinking mode is forced to make an action;
    # thinking mode must use auto because Bailian disallows required there.
    assert first["tool_choice"] == "auto"  # this test passes an empty tools list
    assert second["tool_choice"] == "auto"


def test_bailian_tool_requests_default_to_required_in_non_thinking_mode(tmp_path):
    requests = []
    def handler(req):
        requests.append(json.loads(req.content))
        return httpx.Response(200, json={"choices": [{"finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "tool_calls": [{
                "id": "call-1", "type": "function",
                "function": {"name": "submit_verdict", "arguments": "{}"}
            }]
        }}]})
    cfg = settings(tmp_path, llm_base_url="https://workspace-id.cn-beijing.maas.aliyuncs.com/compatible-mode/v1")
    client = OpenAICompatibleClient(cfg, transport=httpx.MockTransport(handler), thinking="disabled")
    turn = client.complete([{"role": "user", "content": "call tool"}], [TOOLS_FINISH])
    assert requests[0]["tool_choice"] == "required"
    assert requests[0]["enable_thinking"] is False
    assert turn.calls[0].name == "submit_verdict"
    assert turn.finish_reason == "tool_calls"


def test_bailian_thinking_mode_keeps_tool_choice_auto(tmp_path):
    requests = []
    def handler(req):
        requests.append(json.loads(req.content))
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "thinking answer"}}]})
    cfg = settings(tmp_path, llm_base_url="https://workspace-id.cn-beijing.maas.aliyuncs.com/compatible-mode/v1")
    client = OpenAICompatibleClient(cfg, transport=httpx.MockTransport(handler), thinking="enabled")
    client.complete([{"role": "user", "content": "hello"}], [TOOLS_FINISH])
    assert requests[0]["tool_choice"] == "auto"
    assert requests[0]["enable_thinking"] is True


def test_legacy_function_call_response_is_normalized(tmp_path):
    payload = {"choices": [{"finish_reason": "function_call", "message": {
        "role": "assistant", "content": None,
        "function_call": {"name": "submit_verdict", "arguments": "{}"}
    }}]}
    llm = OpenAICompatibleClient(settings(tmp_path), transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json=payload)))
    result = llm.complete([], [TOOLS_FINISH])
    assert result.calls[0].name == "submit_verdict"
    assert result.message["tool_calls"][0]["id"] == "legacy-function-call-1"


def test_provider_429_is_retried_before_failing_or_succeeding(tmp_path, monkeypatch):
    import app.llm as llm_module
    monkeypatch.setattr(llm_module.time, 'sleep', lambda _seconds: None)
    calls = {'count': 0}
    def handler(_req):
        calls['count'] += 1
        if calls['count'] == 1:
            return httpx.Response(429, headers={'Retry-After': '0'}, json={'error': {'message': 'busy'}})
        return httpx.Response(200, json={'choices': [{'message': {
            'role': 'assistant', 'content': None,
            'tool_calls': [{'id': 'ok', 'type': 'function',
                            'function': {'name': 'submit_verdict', 'arguments': '{}'}}]
        }}]})
    llm = OpenAICompatibleClient(settings(tmp_path), transport=httpx.MockTransport(handler))
    result = llm.complete([], [TOOLS_FINISH])
    assert calls['count'] == 2
    assert result.calls[0].name == 'submit_verdict'
