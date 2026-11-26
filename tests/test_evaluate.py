import pytest
from scripts.evaluate_pairs import evaluate


def make_data(vectors):
    truth=[];pred=[]
    for i,(a,b) in enumerate(vectors):
        truth.extend([{'idx':f'{i}v','pair_id':f'p{i}','target':1}, {'idx':f'{i}f','pair_id':f'p{i}','target':0}])
        pred.extend([{'idx':f'{i}v','prediction':a},{'idx':f'{i}f','prediction':b}])
    return truth,pred


def test_pair_categories():
    truth,pred=make_data([(1,0),(1,1),(0,0),(0,1)])
    res=evaluate(truth,pred)
    assert (res['P-C'],res['P-V'],res['P-B'],res['P-R'])==(1,1,1,1)
    assert res['penalty'] is True
    assert res['grade']=='D'


def test_grade_a_no_penalty():
    truth,pred=make_data([(1,0)]*30)
    assert evaluate(truth,pred)['grade']=='A'


def test_grade_penalty():
    truth,pred=make_data([(1,0)]*30+[(0,1)]*16)
    assert evaluate(truth,pred)['grade']=='B'


def test_reject_missing_prediction():
    truth,pred=make_data([(1,0)])
    with pytest.raises(ValueError,match='不完全匹配'):
        evaluate(truth,pred[:1])


def test_reject_ambiguous_pairs():
    truth=[{'idx':'x','target':1,'commit_url':'same'}, {'idx':'y','target':1,'commit_url':'same'}]
    pred=[{'idx':'x','prediction':1},{'idx':'y','prediction':1}]
    with pytest.raises(ValueError,match='重复标签'):
        evaluate(truth,pred)
