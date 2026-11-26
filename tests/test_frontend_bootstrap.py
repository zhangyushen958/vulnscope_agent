"""Regression coverage for frozen config badge and unresponsive model settings."""
from pathlib import Path
from fastapi.testclient import TestClient
from app.web import create_app

STATIC = Path(__file__).resolve().parents[1] / 'app' / 'static'


def test_model_settings_are_independent_and_versioned():
    html = (STATIC / 'index.html').read_text(encoding='utf-8')
    main = (STATIC / 'app.js').read_text(encoding='utf-8')
    model = (STATIC / 'model-settings.js').read_text(encoding='utf-8')
    assert 'model-settings.js?v=3.4.0' in html
    assert 'app.js?v=3.4.0' in html
    assert "$('showModels').addEventListener" not in main
    assert "trigger.addEventListener('click', toggle)" in model
    assert '读取服务状态失败' in model
    assert "cache: 'no-store'" in model


def test_home_assets_have_no_stale_cache():
    client = TestClient(create_app())
    for path in ('/', '/static/model-settings.js', '/static/app.js'):
        response = client.get(path)
        assert response.status_code == 200
        assert 'no-store' in response.headers['cache-control']
