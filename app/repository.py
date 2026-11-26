"""Strict single-version GitHub snapshot acquisition and read-only context tools.

The *only* network egress from this module is to api.github.com for commit
metadata and codeload.github.com for a ZIP at the one resolved SHA. No git diff,
branch checkout, arbitrary URL or shell command is possible.
"""
from __future__ import annotations
import io
import os
import re
import shutil
import stat
import threading
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urljoin
import httpx

SOURCE_EXTS = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".inc", ".inl", ".ipp"}
OWNER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,100}$")
QUALIFIED_IDENT_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:(?:::|->|\.)[A-Za-z_][A-Za-z0-9_]*)+$"
)
MAX_MEMBERS = 200000  # Absolute metadata cap, not a C/C++ source-file limit
MAX_SOURCE_MEMBERS = 50000
MAX_FILE = 2 * 1024 * 1024
MAX_LINES = 180


@dataclass(frozen=True)
class CommitSpec:
    owner: str
    repo: str
    fix_sha: str


def normalize_cpp_identifier(value: str) -> tuple[str, str | None]:
    """Normalize a model-provided symbol expression to one C/C++ identifier.

    The repository index is lexical, not an AST. Models sometimes send a
    qualified name, member expression, declaration or function signature.
    Extract only the callable/member's final identifier; never pass an
    expression, whitespace, regex or source fragment to the scanner.
    """
    if not isinstance(value, str):
        raise ValueError("符号必须是字符串；请传入单个 C/C++ 标识符")
    raw = value.strip().strip("`\"'").strip()
    if not raw or len(raw) > 500 or any(ord(ch) < 32 for ch in raw):
        raise ValueError("符号查询为空或过长；请传入单个 C/C++ 标识符")

    # A function signature / call may include a return type and parameters:
    #   Status Namespace::Open(const char *path)
    #   Namespace::Open(path, flags)
    # Select the first callable designator before its argument list.
    callable_match = re.search(
        r"(?<![A-Za-z0-9_])((?:[A-Za-z_][A-Za-z0-9_]*(?:<[^<>]*>)?::)*"
        r"[A-Za-z_][A-Za-z0-9_]*(?:<[^<>]*>)?)\s*\(", raw
    )
    if callable_match:
        candidate = callable_match.group(1)
        candidate = re.sub(r"<[^<>]*>", "", candidate)
        normalized = candidate.split("::")[-1]
        if IDENT_RE.fullmatch(normalized):
            return normalized, raw

    # Canonical bare identifier (fast path).
    raw = re.sub(r"\s*\(\s*\)\s*(?:const|noexcept|override|final)?\s*$", "", raw)
    raw = raw.lstrip("*& ").rstrip("*& ")
    if IDENT_RE.fullmatch(raw):
        return raw, None

    # Qualified names and member access. Template arguments are removed only
    # when they are a single non-nested suffix.
    no_templates = re.sub(r"<[^<>]*>", "", raw)
    if QUALIFIED_IDENT_RE.fullmatch(no_templates):
        normalized = re.split(r"::|->|\.", no_templates)[-1]
        if IDENT_RE.fullmatch(normalized):
            return normalized, raw

    # Recover the trailing identifier from common declaration-like forms
    # (e.g. "const Foo * object", "definition of reset"). Exclude C/C++ and
    # common English glue words so a natural-language sentence cannot silently
    # turn into an arbitrary keyword search.
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", no_templates)
    ignored = {
        "a", "an", "and", "as", "at", "by", "class", "const", "definition",
        "definitions", "find", "for", "function", "get", "in", "inline", "int",
        "of", "on", "please", "static", "the", "this", "to", "typename", "void",
        "volatile", "where", "with", "struct", "enum", "return", "signed", "unsigned",
        "char", "short", "long", "float", "double", "bool", "auto", "decltype",
    }
    if tokens:
        candidate = tokens[-1]
        looks_like_code_or_qualified_query = any(ch.isspace() for ch in raw) or any(
            marker in raw for marker in ("::", "->", ".", "(", ")", "*", "&")
        )
        if looks_like_code_or_qualified_query and candidate.lower() not in ignored and IDENT_RE.fullmatch(candidate):
            return candidate, raw

    raise ValueError(
        "定义/调用查询只接受一个 C/C++ 标识符。函数签名请只保留函数名；"
        "命名空间或成员表达式请传最后一个名称，例如 `AcquireString`、`reset`。"
    )


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def parse_commit_url(url: str) -> CommitSpec:
    parsed = urlsplit(url)
    # An explicit, domain-locked historical mirror alias present in the supplied
    # test dataset. No arbitrary Git host or URL may be used for network access.
    if (parsed.scheme == "https" and parsed.hostname == "git.qemu.org" and
            parsed.path == "/" and parsed.port in (None, 443) and not parsed.fragment):
        match = re.fullmatch(r"p=qemu\.git;a=commit;h=([0-9a-fA-F]{40})", parsed.query)
        if match:
            return CommitSpec("qemu", "qemu", match.group(1).lower())
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.port not in (None, 443):
        raise ValueError("只允许 https://github.com/{owner}/{repo}/commit/{sha} 链接")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("提交链接不能包含凭据、参数或片段")
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 4 or parts[2] != "commit":
        raise ValueError("提交链接格式必须为 /owner/repo/commit/sha")
    owner, repo, _, sha = parts
    if not (OWNER_RE.fullmatch(owner) and OWNER_RE.fullmatch(repo) and SHA_RE.fullmatch(sha)):
        raise ValueError("仓库名称或提交 SHA 格式不合法")
    if owner in {".", ".."} or repo in {".", ".."}:
        raise ValueError("仓库路径不合法")
    return CommitSpec(owner, repo, sha.lower())


class SnapshotProvider:
    def __init__(self, cache_dir: Path, github_token: str = "", max_bytes: int = 100 * 1024 * 1024,
                 transport: httpx.BaseTransport | None = None,
                 max_uncompressed: int | None = None):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.github_token = github_token
        self.max_bytes = max_bytes  # compressed GitHub ZIP download limit
        self.max_uncompressed = max_uncompressed if max_uncompressed is not None else max_bytes
        self.transport = transport
        self._lock = threading.RLock()
        self._commit_cache: dict[tuple[str, str, str], tuple[float, dict]] = {}
        self._api_redirects: dict[str, str] = {}
        self._api_cooldown_until = 0.0
        self._api_cooldown_message = ""

    def _client(self, *, include_token: bool = True) -> httpx.Client:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "VulnScope-StrictSnapshot/1.0"}
        if include_token and self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return httpx.Client(headers=headers, timeout=httpx.Timeout(35, connect=8), follow_redirects=False,
                            transport=self.transport)

    def _github_json(self, client: httpx.Client, url: str) -> dict:
        """Fetch commit metadata with same-host redirects and explicit rate-limit handling."""
        now = time.time()
        if now < self._api_cooldown_until:
            seconds = max(1, int(self._api_cooldown_until - now))
            raise RuntimeError(
                f"GitHub REST API 暂时处于限流冷却期，约 {seconds} 秒后可重试。"
                "未认证公开 REST API 配额通常只有每小时 60 次；建议在 .env 配置 "
                "VULNSCOPE_GITHUB_TOKEN（GitHub 访问令牌），并在限流窗口重置后重新运行。"
            )
        current = self._api_redirects.get(url, url)
        redirects = 0
        while True:
            response = client.get(current)
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("location")
                target = urljoin(current, location or "")
                parsed = urlsplit(target)
                if parsed.scheme != "https" or parsed.hostname != "api.github.com" or parsed.port not in (None, 443):
                    raise RuntimeError("GitHub API 返回了非可信域名重定向，已拒绝跟随")
                redirects += 1
                if redirects > 5:
                    raise RuntimeError("GitHub API 重定向次数超过安全上限")
                if response.status_code == 301:
                    self._api_redirects[url] = target
                current = target
                continue
            if response.status_code in (403, 429):
                remaining = response.headers.get("x-ratelimit-remaining")
                reset = response.headers.get("x-ratelimit-reset")
                retry_after = _retry_after_seconds(response.headers.get("retry-after"))
                body = response.text[:500].lower()
                is_rate_limited = remaining == "0" or "rate limit" in body or "secondary rate" in body
                if is_rate_limited:
                    try:
                        cooldown = max(0.0, float(reset) - time.time()) if reset else 0.0
                    except (TypeError, ValueError):
                        cooldown = 0.0
                    if cooldown <= 0:
                        cooldown = retry_after if retry_after is not None else 60.0
                    self._api_cooldown_until = time.time() + cooldown
                    reset_text = f"，预计 {int(cooldown)} 秒后重置" if cooldown else ""
                    auth_hint = (
                        "当前未配置 VULNSCOPE_GITHUB_TOKEN；匿名公开 REST API 配额通常为每小时 60 次。"
                        if not self.github_token else
                        "当前已配置令牌；请检查令牌额度、权限或 GitHub 次级限流响应头。"
                    )
                    self._api_cooldown_message = (
                        "GitHub REST API 已触发 403/429 限流" + reset_text +
                        "。该限制与百炼模型 API 无关。" + auth_hint +
                        "等待 GitHub 限流窗口重置后重试。"
                    )
                    raise RuntimeError(self._api_cooldown_message)
            response.raise_for_status()
            return response.json()

    def _download_archive(self, client: httpx.Client, url: str, output) -> None:
        """Stream codeload ZIP with bounded transient-error retries."""
        current = url
        redirects = 0
        last_status = None
        for attempt in range(3):
            output.seek(0)
            output.truncate(0)
            retry_request = False
            while True:
                try:
                    with client.stream("GET", current) as response:
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("location")
                            target = urljoin(current, location or "")
                            parsed = urlsplit(target)
                            if parsed.scheme != "https" or parsed.hostname != "codeload.github.com" or parsed.port not in (None, 443):
                                raise RuntimeError("仓库 ZIP 返回了非可信域名重定向，已拒绝跟随")
                            redirects += 1
                            if redirects > 5:
                                raise RuntimeError("仓库 ZIP 重定向次数超过安全上限")
                            current = target
                            continue
                        last_status = response.status_code
                        if response.status_code in (429, 500, 502, 503, 504):
                            if attempt >= 2:
                                raise RuntimeError(
                                    f"GitHub codeload 在有限重试后仍返回 HTTP {response.status_code}；"
                                    "请降低批量并发或稍后重试。"
                                )
                            delay = _retry_after_seconds(response.headers.get("retry-after"))
                            if delay is None:
                                delay = float(2 ** attempt)
                            if delay > 30:
                                raise RuntimeError(
                                    f"GitHub codeload 返回 HTTP {response.status_code}，要求等待 {int(delay)} 秒；"
                                    "请稍后重试，避免继续触发限流。"
                                )
                            time.sleep(delay)
                            retry_request = True
                            break
                        response.raise_for_status()
                        downloaded = 0
                        for chunk in response.iter_bytes(chunk_size=65536):
                            downloaded += len(chunk)
                            if downloaded > self.max_bytes:
                                limit_mb = self.max_bytes / (1024 * 1024)
                                raise ValueError(
                                    f"仓库快照压缩包超过 {limit_mb:.0f} MiB 下载限制；"
                                    "可在 .env 调高 VULNSCOPE_MAX_REPO_ARCHIVE_MB（范围 10～512），然后重启服务。"
                                )
                            output.write(chunk)
                        return
                except (httpx.ConnectError, httpx.TimeoutException):
                    if attempt >= 2:
                        raise
                    time.sleep(float(2 ** attempt))
                    retry_request = True
                    break
            if not retry_request:
                break
        raise RuntimeError(f"GitHub codeload 请求重试后仍失败（HTTP {last_status or 'unknown'}）")

    def _resolve_ref(self, spec: CommitSpec, target: int, client: httpx.Client) -> str:
        if type(target) is not int or target not in (0, 1):
            raise ValueError("target 必须是 0 或 1；不能猜测仓库版本")
        cache_key = (spec.owner.lower(), spec.repo.lower(), spec.fix_sha.lower())
        cached = self._commit_cache.get(cache_key)
        if cached and time.time() - cached[0] < 3600:
            obj = cached[1]
        else:
            api = f"https://api.github.com/repos/{spec.owner}/{spec.repo}/commits/{spec.fix_sha}"
            obj = self._github_json(client, api)
            self._commit_cache[cache_key] = (time.time(), obj)
        sha = obj.get("sha", "")
        if not (isinstance(sha, str) and re.fullmatch(r"[a-fA-F0-9]{40}", sha)):
            raise ValueError("提交 API 未返回完整 SHA")
        if target == 0:
            return sha.lower()  # fixed version: snapshot at fixing commit
        parents = obj.get("parents") or []
        if not parents:
            raise ValueError("该提交没有父提交，无法取得漏洞版快照")
        parent_sha = parents[0].get("sha", "")
        if not isinstance(parent_sha, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", parent_sha):
            raise ValueError("无法验证父提交 SHA")
        return parent_sha.lower()  # vulnerable version: first parent ONLY

    def fetch(self, commit_url: str, target: int) -> tuple[Path, str]:
        spec = parse_commit_url(commit_url)
        with self._client(include_token=True) as api_client, self._client(include_token=False) as archive_client:
            sha = self._resolve_ref(spec, target, api_client)
            key = f"{spec.owner.lower()}__{spec.repo.lower()}__{sha}"
            dest = self.cache_dir / key
            with self._lock:
                if (dest / ".snapshot_ready").is_file():
                    return dest, sha
                url = f"https://codeload.github.com/{spec.owner}/{spec.repo}/zip/{sha}"
                # Stream the compressed archive to a temporary file instead of
                # retaining the whole ZIP in RAM. Large source repositories can
                # otherwise duplicate hundreds of MiB during BytesIO/getvalue().
                download_path: Path | None = None
                staging = self.cache_dir / (key + ".extracting")
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="wb", prefix=key + ".", suffix=".zip",
                        dir=self.cache_dir, delete=False
                    ) as download:
                        download_path = Path(download.name)
                        self._download_archive(archive_client, url, download)
                    if staging.exists():
                        shutil.rmtree(staging)
                    staging.mkdir(parents=True)
                    extract_safe_source_zip(download_path, staging, max_uncompressed=self.max_uncompressed)
                    (staging / ".snapshot_ready").write_text(sha, encoding="ascii")
                    if dest.exists():
                        shutil.rmtree(dest)
                    staging.rename(dest)
                except Exception:
                    shutil.rmtree(staging, ignore_errors=True)
                    raise
                finally:
                    if download_path is not None:
                        download_path.unlink(missing_ok=True)
                return dest, sha


def extract_safe_source_zip(archive: bytes | bytearray | Path, destination: Path,
                            max_uncompressed: int = 100 * 1024 * 1024) -> int:
    """Allowlist source files, reject malicious ZIP paths and decompression bombs.

    ``archive`` may be bytes (for tests/compatibility) or a seekable ZIP path.
    """
    total = count = 0
    archive_root = None
    source = io.BytesIO(archive) if isinstance(archive, (bytes, bytearray)) else archive
    with zipfile.ZipFile(source) as z:
        items = z.infolist()
        if len(items) > MAX_MEMBERS:
            raise ValueError(f"仓库归档包含 {len(items)} 个条目，超过安全上限 {MAX_MEMBERS}；可提高限制或改用精确目录检索")
        for item in items:
            raw = item.filename
            pp = PurePosixPath(raw)
            if raw.startswith("/") or "\\" in raw or "\x00" in raw or ".." in pp.parts:
                raise ValueError("仓库归档包含危险路径")
            if not pp.parts:
                raise ValueError("仓库归档包含空路径")
            if archive_root is None:
                archive_root = pp.parts[0]
            elif pp.parts[0] != archive_root:
                raise ValueError("仓库归档包含多个根目录，拒绝混合快照")
            # GitHub ZIPs include a single root-directory entry; skip it safely.
            if item.is_dir():
                continue
            if len(pp.parts) < 2:
                raise ValueError("仓库归档源文件没有顶层目录")
            if any(part == ".git" for part in pp.parts):
                continue
            if pp.suffix.lower() not in SOURCE_EXTS:
                continue
            if stat.S_IFMT(item.external_attr >> 16) == stat.S_IFLNK:
                continue
            if item.file_size > MAX_FILE:
                continue
            if count >= MAX_SOURCE_MEMBERS:
                raise ValueError("仓库 C/C++ 源文件数量超过安全限制")
            total += item.file_size
            if total > max_uncompressed:
                actual_mb = total / (1024 * 1024)
                limit_mb = max_uncompressed / (1024 * 1024)
                raise ValueError(
                    f"仓库源码总量超过限制：允许的 C/C++ 源码解压总量为 {limit_mb:.0f} MiB，"
                    f"当前至少需要 {actual_mb:.1f} MiB。请在项目根目录 .env 将 "
                    "VULNSCOPE_MAX_REPO_MB 调高（范围 10～1024），然后重启服务。"
                )
            # Strip the ZIP's top-level repo-sha root; never trust that root name.
            pieces = pp.parts[1:]
            if any(p in {"", ".", ".."} for p in pieces):
                raise ValueError("ZIP 文件路径含有非法段")
            dest = destination.joinpath(*pieces)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(item) as src, dest.open("wb") as dst:
                while True:
                    part = src.read(65536)
                    if not part:
                        break
                    dst.write(part)
            count += 1
    if count == 0:
        raise ValueError("归档中没有允许的 C/C++ 源码文件")
    return count


class RepositoryTools:
    """Read-only, snapshot-scoped context inspection; never exposes other commits."""
    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self.files = sorted(x for x in self.root.rglob("*") if x.is_file() and x.suffix.lower() in SOURCE_EXTS
                            and not x.is_symlink() and ".git" not in x.parts)[:10000]
        self._files_by_rel = {x.relative_to(self.root).as_posix(): x for x in self.files}

    def _file(self, rel: str) -> Path:
        if not isinstance(rel, str) or len(rel) > 400 or "\x00" in rel or "\\" in rel:
            raise ValueError("文件路径不合法")
        rel_path = PurePosixPath(rel)
        if rel_path.is_absolute() or ".." in rel_path.parts or rel_path.suffix.lower() not in SOURCE_EXTS:
            raise ValueError("不允许读取快照外部或非源码文件")
        normalized = rel_path.as_posix()
        requested_candidate = self.root / str(rel_path)
        if requested_candidate.is_symlink() or any(
            parent.is_symlink() for parent in requested_candidate.parents if parent != self.root
        ):
            raise ValueError("禁止通过符号链接读取源码")
        candidate = self._files_by_rel.get(normalized)
        if candidate is None:
            from difflib import get_close_matches
            suggestions = get_close_matches(normalized, list(self._files_by_rel), n=3, cutoff=0.55)
            hint = f"；相近路径：{', '.join(suggestions)}" if suggestions else ""
            raise ValueError(
                f"文件不在当前已加载的 C/C++ 快照中：{normalized}{hint}。"
                "请从 search_code/find_definitions 返回结果中复制 path，不要猜测路径。"
            )
        if candidate.is_symlink() or any(parent.is_symlink() for parent in candidate.parents if parent != self.root):
            raise ValueError("禁止通过符号链接读取源码")
        path = candidate.resolve(strict=False)
        if not path.is_relative_to(self.root) or not path.is_file():
            raise ValueError("文件不在已授权的快照中")
        if path.stat().st_size > MAX_FILE:
            raise ValueError("文件超出读取限制")
        return path

    def read_file(self, path: str, start_line: int = 1, end_line: int = 90) -> dict:
        f = self._file(path)
        start = max(1, min(100000, int(start_line)))
        end = min(start + MAX_LINES - 1, max(start, int(end_line)))
        lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(start - 1, min(end, len(lines))))
        return {"path": str(f.relative_to(self.root)).replace(os.sep, "/"), "range": [start, min(end, len(lines))],
                "total_lines": len(lines), "content": snippet[:16000]}

    def search_code(self, symbol: str, max_hits: int = 16) -> dict:
        if not isinstance(symbol, str):
            raise ValueError("检索词必须是字符串")
        symbol = symbol.strip().strip("`\"'").strip()
        if not (1 <= len(symbol) <= 100) or "\n" in symbol or "\r" in symbol or any(ord(c) < 32 for c in symbol):
            raise ValueError("检索词长度需在 1~100 字符之间，且不得含换行或控制字符")
        # Literal matching prevents injected regex patterns and catastrophic backtracking.
        needle = symbol.lower()
        results = []
        for f in self.files:
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if needle in line.lower():
                    results.append({"path": f.relative_to(self.root).as_posix(), "line": i, "snippet": line.strip()[:320]})
                    if len(results) >= max(1, min(32, int(max_hits))):
                        return {"query": symbol, "matches": results, "truncated": True}
        return {"query": symbol, "matches": results, "truncated": False}

    def find_callers(self, symbol: str) -> dict:
        symbol, normalized_from = normalize_cpp_identifier(symbol)
        # Lightweight lexical scan. Callers may include declarations/comments; LLM must verify.
        pattern = re.compile(r"\b" + re.escape(symbol) + r"\s*\(")
        results = []
        for f in self.files:
            text = f.read_text(encoding="utf-8", errors="replace")
            for n, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    results.append({"path": f.relative_to(self.root).as_posix(), "line": n, "snippet": line.strip()[:250]})
                    if len(results) >= 24:
                        return {"symbol": symbol, "normalized_from": normalized_from,
                                "matches": results, "truncated": True,
                                "note": "词法近似结果，可能包含声明、定义或注释；需读取上下文确认"}
        return {"symbol": symbol, "normalized_from": normalized_from,
                "matches": results, "truncated": False,
                "note": "词法近似结果，非精确 AST 调用图"}

    def find_definitions(self, symbol: str) -> dict:
        symbol, normalized_from = normalize_cpp_identifier(symbol)
        found = self.search_code(symbol, max_hits=20)
        found["normalized_from"] = normalized_from
        found["note"] = "检索标识符的可能定义、类型、宏、全局变量或使用处；需进一步 read_file 核验"
        return found
