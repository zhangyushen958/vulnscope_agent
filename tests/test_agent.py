import pytest
from app.agent import VulnerabilityAgent, LANGGRAPH_AVAILABLE
from app.llm import ModelTurn, ToolCall
from app.models import DetectionInput
from app.repository import RepositoryTools


class ScriptedModel:
    def __init__(self, actions):
        self.actions=list(actions)
        self.seen=[]
        self.schema=[]
    def complete(self,messages,tools):
        self.seen.append(messages)
        self.schema.append([x['function']['name'] for x in tools])
        name,args=self.actions.pop(0)
        call=ToolCall(id=f'call-{len(self.seen)}',name=name,arguments=args)
        msg={'role':'assistant','content':None,'tool_calls':[{'type':'function','id':call.id,'function':{'name':name,'arguments':'{}'}}]}
        return ModelTurn(message=msg,calls=[call])


class MultiToolModel:
    def __init__(self, turns):
        self.turns = list(turns)
        self.seen = []
        self.schemas = []

    def complete(self, messages, tools):
        from app.llm import ToolCall
        self.seen.append(messages)
        self.schemas.append([x['function']['name'] for x in tools])
        actions = self.turns.pop(0)
        calls = [ToolCall(id=f'multi-{len(self.seen)}-{i}', name=name, arguments=args)
                  for i, (name, args) in enumerate(actions)]
        message = {'role': 'assistant', 'content': None,
                   'tool_calls': [{'id': c.id, 'type': 'function',
                                   'function': {'name': c.name, 'arguments': '{}'}} for c in calls]}
        return ModelTurn(message=message, calls=calls)


SAMPLE='int process(int n) { return helper(n); }'
VERDICT={'prediction':0,'reason':'函数调用 helper 后直接返回，输入与依赖状态需结合代码审查；未找到确定性漏洞证据。',
         'confidence':0.65,'evidence':['当前函数第 1 行']}


def test_agent_retrieves_then_decides_no_repo(kb):
    m=ScriptedModel([('submit_verdict',VERDICT)])
    item=DetectionInput(idx=102,func=SAMPLE)
    report=VulnerabilityAgent(kb,m).detect(item)
    assert report.idx==102 and report.prediction==0
    assert report.trace[0].kind=='knowledge'
    assert any(x.kind=='decision' for x in report.trace)
    assert 'find_callers' not in m.schema[0]


def test_agent_has_autonomous_repository_loop(kb,repository):
    m=ScriptedModel([('find_callers',{'symbol':'helper'}),('read_file',{'path':'module.c','start_line':1,'end_line':5}),('submit_verdict',VERDICT)])
    logs=[]
    report=VulnerabilityAgent(kb,m).detect(DetectionInput(idx='A',func=SAMPLE), RepositoryTools(repository),logs.append)
    assert len(m.seen)==3
    assert sum(x.kind=='repository' for x in report.trace)==2
    assert any(x['kind']=='repository' for x in logs)
    assert 'find_callers' in m.schema[0]
    # A real tool-result message is passed into the next model decision.
    assert any(x.get('role')=='tool' and 'module.c' in x.get('content','') for x in m.seen[-1])


def test_no_test_label_or_commit_url_in_prompt(kb,repository):
    m=ScriptedModel([('submit_verdict',VERDICT)])
    item=DetectionInput(idx='secret',func=SAMPLE,target=1,
                        commit_url='https://github.com/foo/bar/commit/'+'a'*40)
    VulnerabilityAgent(kb,m).detect(item,RepositoryTools(repository))
    whole=str(m.seen)
    assert item.commit_url not in whole
    assert 'target=1' not in whole
    assert 'secret' not in whole


def test_unexpected_tool_denied(kb):
    m=ScriptedModel([('web_search',{'query':'find CVE'}),('submit_verdict',VERDICT)])
    result=VulnerabilityAgent(kb,m).detect(DetectionInput(idx=1,func=SAMPLE))
    assert any(x.title=='拒绝未授权工具调用' for x in result.trace)


def test_invalid_verdict_rejected(kb):
    invalid={**VERDICT,'prediction':'1'}
    m=ScriptedModel([('submit_verdict',invalid),('submit_verdict',VERDICT)])
    result=VulnerabilityAgent(kb,m).detect(DetectionInput(idx=1,func=SAMPLE))
    assert result.prediction==0
    assert any(x.title=='拒绝不完整判定' for x in result.trace)


def test_max_steps_fails_closed(kb):
    m=ScriptedModel([('retrieve_more_cases',{'query':'pointer'}),('retrieve_more_cases',{'query':'pointer'})])
    with pytest.raises(RuntimeError,match='最大推理轮次'):
        VulnerabilityAgent(kb,m,max_steps=2).detect(DetectionInput(idx=1,func=SAMPLE))


def test_kb_empty_not_fabricated(tmp_path):
    from app.rag import HistoricalKB
    kb=HistoricalKB(tmp_path/'empty.json')
    m=ScriptedModel([('submit_verdict',VERDICT)])
    result=VulnerabilityAgent(kb,m).detect(DetectionInput(idx=1,func=SAMPLE))
    assert any(x.kind=='warning' and '知识库' in x.title for x in result.trace)


def test_parallel_verdict_requires_observing_tool_result(kb,repository):
    # Multi-tool turn cannot simultaneously query code and submit a verdict
    # because the model hasn't seen the tool evidence yet.
    class ParallelOnce:
        def __init__(self):self.n=0
        def complete(self,messages,tools):
            self.n+=1
            if self.n==1:
                calls=[ToolCall('a','find_callers',{'symbol':'helper'}),
                       ToolCall('b','submit_verdict',VERDICT)]
            else:
                calls=[ToolCall('c','submit_verdict',VERDICT)]
            msg={'role':'assistant','content':None,'tool_calls':[{'type':'function','id':c.id,
                'function':{'name':c.name,'arguments':'{}'}} for c in calls]}
            return ModelTurn(message=msg,calls=calls)
    model=ParallelOnce()
    report=VulnerabilityAgent(kb,model).detect(DetectionInput(idx=1,func=SAMPLE),RepositoryTools(repository))
    assert model.n==2
    assert any(e.title=='拒绝与其他工具并行的最终判定' for e in report.trace)


def test_too_many_tools_in_one_turn_are_partially_rejected_not_sample_fatal(kb):
    model = MultiToolModel([
        [('retrieve_more_cases', {'query': 'pointer'}) for _ in range(5)],
        [('submit_verdict', VERDICT)],
    ])
    report = VulnerabilityAgent(kb, model, max_steps=6).detect(DetectionInput(idx=321, func=SAMPLE))
    assert report.prediction == 0
    assert any(e.title == '单轮工具请求过多，已安全截取' for e in report.trace)
    # Agent executes at most two requests from one model turn.
    assert sum(e.title == 'Agent 按需二次检索历史案例' for e in report.trace) == 2


def test_agent_switches_to_verdict_before_research_tool_budget_is_exhausted(kb):
    model = MultiToolModel([
        [('retrieve_more_cases', {'query': f'pointer {i}'}) for i in range(4)],
        [('retrieve_more_cases', {'query': 'another pointer'}) for _ in range(2)],
        [('submit_verdict', VERDICT)],
    ])
    report = VulnerabilityAgent(kb, model, max_steps=6, max_tool_calls=8).detect(
        DetectionInput(idx=322, func=SAMPLE))
    assert report.prediction == 0
    assert model.schemas[2] == ['submit_verdict']


def test_agent_reserves_last_reasoning_turns_for_verdict(kb):
    model = MultiToolModel([
        [('retrieve_more_cases', {'query': 'pointer'})],
        [('submit_verdict', VERDICT)],
    ])
    report = VulnerabilityAgent(kb, model, max_steps=3).detect(DetectionInput(idx=323, func=SAMPLE))
    assert report.prediction == 0
    assert model.schemas[1] == ['submit_verdict']
