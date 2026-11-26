import io
import json
import stat
import zipfile
from pathlib import Path
import httpx
import pytest
from app.repository import (parse_commit_url, SnapshotProvider, extract_safe_source_zip,
                            RepositoryTools, normalize_cpp_identifier)
from tests.conftest import make_zip

SHA='a'*40
PARENT='b'*40
URL=f'https://github.com/org/project/commit/{SHA}'

@pytest.mark.parametrize('bad', [
    f'http://github.com/org/project/commit/{SHA}',
    f'https://github.com.evil.site/org/project/commit/{SHA}',
    f'https://github.com/org/project/compare/{SHA}',
    f'https://github.com/org/project/commit/{SHA}?foo=x',
    'file:///etc/passwd',
    'https://github.com/org/project/commit/notasha',
    f'https://u:pw@github.com/org/project/commit/{SHA}',
])
def test_invalid_commit_urls(bad):
    with pytest.raises(ValueError):
        parse_commit_url(bad)


def test_valid_commit_url():
    spec=parse_commit_url(URL)
    assert (spec.owner,spec.repo,spec.fix_sha)==('org','project',SHA)


def test_snapshot_parent_vs_fixed(tmp_path):
    seen=[]
    def handler(req):
        seen.append(str(req.url))
        if req.url.host=='api.github.com':
            return httpx.Response(200,json={'sha':SHA,'parents':[{'sha':PARENT}]})
        assert req.url.host=='codeload.github.com'
        return httpx.Response(200,content=make_zip({'project-ref/module.c':'int ok() { return 1; }','project-ref/README.md':'text'}))
    provider=SnapshotProvider(tmp_path,transport=httpx.MockTransport(handler))
    parent_path,parent_sha=provider.fetch(URL,1)
    fixed_path,fixed_sha=provider.fetch(URL,0)
    assert parent_sha==PARENT
    assert fixed_sha==SHA
    assert parent_path!=fixed_path
    assert (parent_path/'module.c').exists()
    assert not (fixed_path/'README.md').exists()
    assert any('/zip/'+PARENT in x for x in seen)
    assert any('/zip/'+SHA in x for x in seen)
    assert all(x.startswith('https://api.github.com/') or x.startswith('https://codeload.github.com/') for x in seen)
    # Vulnerable/fixed target pair shares commit metadata and should use one REST call.
    assert sum(x.startswith('https://api.github.com/') for x in seen) == 1


def test_github_api_301_redirect_is_followed_safely(tmp_path):
    calls = []
    redirected = f"https://api.github.com/repositories/123/commits/{SHA}"

    def handler(req):
        calls.append((str(req.url), req.headers.get('authorization')))
        if req.url.host == 'api.github.com' and req.url.path.startswith('/repos/'):
            return httpx.Response(301, headers={'Location': redirected})
        if req.url.host == 'api.github.com':
            return httpx.Response(200, json={'sha': SHA, 'parents': [{'sha': PARENT}]})
        return httpx.Response(200, content=make_zip({'project-ref/module.c': 'int x(void) { return 1; }'}))

    provider = SnapshotProvider(tmp_path, github_token='gh-token', transport=httpx.MockTransport(handler))
    provider.fetch(URL, 0)
    assert any(url == redirected for url, _ in calls)
    # The token is sent to api.github.com only, never to codeload.github.com.
    assert all(auth == 'Bearer gh-token' for url, auth in calls if 'api.github.com' in url)
    assert all(auth is None for url, auth in calls if 'codeload.github.com' in url)


def test_github_api_rate_limit_reports_token_and_cooldown(tmp_path):
    calls = []
    def handler(req):
        calls.append(str(req.url))
        return httpx.Response(403, headers={
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': str(int(__import__('time').time()) + 120),
        }, json={'message': 'API rate limit exceeded'})

    provider = SnapshotProvider(tmp_path, transport=httpx.MockTransport(handler))
    with pytest.raises(RuntimeError, match='VULNSCOPE_GITHUB_TOKEN'):
        provider.fetch(URL, 0)
    with pytest.raises(RuntimeError, match='冷却期'):
        provider.fetch(URL, 0)
    assert len(calls) == 1


def test_codeload_429_is_retried(tmp_path, monkeypatch):
    import app.repository as repository_module
    monkeypatch.setattr(repository_module.time, 'sleep', lambda _seconds: None)
    count = {'api': 0, 'zip': 0}

    def handler(req):
        if req.url.host == 'api.github.com':
            count['api'] += 1
            return httpx.Response(200, json={'sha': SHA, 'parents': [{'sha': PARENT}]})
        count['zip'] += 1
        if count['zip'] == 1:
            return httpx.Response(429, headers={'Retry-After': '0'}, text='rate limited')
        return httpx.Response(200, content=make_zip({'project-ref/module.c': 'int x(void) { return 1; }'}))

    provider = SnapshotProvider(tmp_path, transport=httpx.MockTransport(handler))
    root, _ = provider.fetch(URL, 0)
    assert (root / 'module.c').is_file()
    assert count == {'api': 1, 'zip': 2}


def test_no_parent_rejects(tmp_path):
    def handler(req):return httpx.Response(200,json={'sha':SHA,'parents':[]})
    provider=SnapshotProvider(tmp_path,transport=httpx.MockTransport(handler))
    with pytest.raises(ValueError,match='父提交'):
        provider.fetch(URL,1)


def test_invalid_label_rejects_before_network(tmp_path):
    provider=SnapshotProvider(tmp_path)
    with pytest.raises(ValueError,match='target'):
        provider.fetch(URL,2)


def test_reject_zip_path_traversal(tmp_path):
    with pytest.raises(ValueError,match='危险路径'):
        extract_safe_source_zip(make_zip({'project-ref/../../escape.c':'int x;'}),tmp_path)
    assert not (tmp_path.parent/'escape.c').exists()


def test_ignore_noncode_and_symlink(tmp_path):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z:
        link=zipfile.ZipInfo('project-ref/link.c')
        link.create_system=3
        link.external_attr=(stat.S_IFLNK | 0o777) <<16
        z.writestr(link,'/etc/passwd')
        z.writestr('project-ref/main.c','int x;')
        z.writestr('project-ref/change.diff','untrusted diff')
        z.writestr('project-ref/.git/config','private')
    assert extract_safe_source_zip(buf.getvalue(),tmp_path)==1
    assert not (tmp_path/'link.c').exists()
    assert not (tmp_path/'change.diff').exists()


def test_read_scope_and_tools(repository,tmp_path):
    repo=RepositoryTools(repository)
    assert len(repo.files)==2
    assert 'helper' in repo.read_file('module.c')['content']
    assert repo.find_callers('helper')['matches']
    assert repo.find_definitions('LENGTH')['matches']
    assert repo.search_code('shared_count')['matches']
    assert repo.search_code('i')['matches']  # one-character C identifier is a valid literal query
    for path in ['../README.md','/etc/passwd','readme.txt','module.c/../../etc/passwd']:
        with pytest.raises((ValueError,FileNotFoundError)):
            repo.read_file(path)


def test_symlink_escape(repository,tmp_path):
    (repository/'external.c').symlink_to(tmp_path/'else.c')
    (tmp_path/'else.c').write_text('int secret();')
    repo=RepositoryTools(repository)
    with pytest.raises(ValueError):
        repo.read_file('external.c')


def test_github_zip_root_dir_entry_is_accepted(tmp_path):
    # GitHub codeload adds an explicit top-level `repo-sha/` directory entry.
    archive=make_zip({'project-ref/':'', 'project-ref/module.c':'int x(){return 0;}'})
    assert extract_safe_source_zip(archive,tmp_path)==1
    assert (tmp_path/'module.c').is_file()


def test_reject_mixed_roots(tmp_path):
    archive=make_zip({'repo-old/a.c':'int old;', 'repo-new/b.c':'int new;'})
    with pytest.raises(ValueError,match='多个根目录'):
        extract_safe_source_zip(archive,tmp_path)


def test_symlink_within_root_is_also_refused(repository):
    (repository/'internal.c').symlink_to(repository/'module.c')
    repo=RepositoryTools(repository)
    with pytest.raises(ValueError,match='符号链接'):
        repo.read_file('internal.c')


@pytest.mark.parametrize(('raw', 'normalized'), [
    ('AcquireString', 'AcquireString'),
    ('MagickCore::AcquireString', 'AcquireString'),
    ('image->exception', 'exception'),
    ('image.profile', 'profile'),
    ('MagickCore::Image<T>::reset', 'reset'),
    ('MagickCore::AcquireString(source, length)', 'AcquireString'),
    ('Status MagickCore::AcquireString(const char *source, size_t length)', 'AcquireString'),
    ('int Graph::AddEdge(Node *source, int x, Node *dest, int y)', 'AddEdge'),
    ('const char * GetText(const char *text)', 'GetText'),
    ('const Image *image', 'image'),
])
def test_cpp_symbol_queries_are_normalized(raw, normalized):
    actual, original = normalize_cpp_identifier(raw)
    assert actual == normalized
    if actual == raw:
        assert original is None
    else:
        assert original == raw


def test_single_character_literal_search_is_allowed(repository):
    repo = RepositoryTools(repository)
    result = repo.search_code('x')
    assert result['query'] == 'x'


def test_read_missing_file_returns_safe_snapshot_guidance(repository):
    repo = RepositoryTools(repository)
    with pytest.raises(ValueError, match='当前已加载.*快照'):
        repo.read_file('not_present.c')


def test_extract_safe_source_zip_from_disk_path(tmp_path):
    archive_path = tmp_path / "snapshot.zip"
    archive_path.write_bytes(make_zip({"project-ref/src/main.c": "int main(void) { return 0; }"}))
    destination = tmp_path / "extracted"
    destination.mkdir()
    assert extract_safe_source_zip(archive_path, destination, max_uncompressed=1024) == 1
    assert (destination / "src/main.c").is_file()


def test_source_budget_error_explains_env_override(tmp_path):
    archive = make_zip({"project-ref/a.c": "int first_function(void) { return 0; }"})
    with pytest.raises(ValueError, match="VULNSCOPE_MAX_REPO_MB"):
        extract_safe_source_zip(archive, tmp_path, max_uncompressed=8)


def test_snapshot_provider_has_independent_archive_and_source_budgets(tmp_path):
    archive = make_zip({"project-ref/a.c": "int first_function(void) { return 0; }"})

    def handler(req):
        if req.url.host == "api.github.com":
            return httpx.Response(200, json={"sha": SHA, "parents": [{"sha": PARENT}]})
        return httpx.Response(200, content=archive)

    provider = SnapshotProvider(
        tmp_path, transport=httpx.MockTransport(handler),
        max_bytes=len(archive) + 100, max_uncompressed=8,
    )
    with pytest.raises(ValueError, match="VULNSCOPE_MAX_REPO_MB"):
        provider.fetch(URL, 0)
    assert not list(tmp_path.glob("*.zip"))
    assert not list(tmp_path.glob("*.extracting"))
