"""
Tests for mcp_server._app._load_dotenv.

_load_dotenv reads a .env file from the project root and injects
missing keys into os.environ without overwriting existing ones.
"""
import os
import pytest
from mcp_server._app import _load_dotenv


def _write_env(tmp_path, content: str) -> str:
    """Write .env content to a temp file and return its parent dir path."""
    env_file = tmp_path / ".env"
    env_file.write_text(content)
    return str(tmp_path)


def test_load_dotenv_sets_missing_key(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("MY_KEY=my_value\n")
    monkeypatch.delenv("MY_KEY", raising=False)

    # Patch the path that _load_dotenv constructs
    with monkeypatch.context() as m:
        m.setattr(os.path, "dirname", lambda _: str(tmp_path / "mcp_server"))
        # _load_dotenv builds: os.path.dirname(os.path.dirname(__file__)) / ".env"
        # We patch os.path.isfile and open instead for a more reliable approach
        pass

    # Direct approach: write a real .env relative to a temp dir and invoke
    # _load_dotenv with a monkeypatched __file__ path
    env_file2 = tmp_path / ".env"
    env_file2.write_text("DIRECT_TEST_KEY=hello\n")
    monkeypatch.delenv("DIRECT_TEST_KEY", raising=False)

    original = os.path.join
    def patched_join(a, b):
        if b == ".env":
            return str(env_file2)
        return original(a, b)

    monkeypatch.setattr(os.path, "join", patched_join)
    _load_dotenv()
    assert os.environ.get("DIRECT_TEST_KEY") == "hello"


def test_load_dotenv_does_not_overwrite_existing(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("EXISTING_KEY=from_file\n")
    monkeypatch.setenv("EXISTING_KEY", "from_env")

    original = os.path.join
    def patched_join(a, b):
        if b == ".env":
            return str(env_file)
        return original(a, b)

    monkeypatch.setattr(os.path, "join", patched_join)
    _load_dotenv()
    assert os.environ["EXISTING_KEY"] == "from_env"


def test_load_dotenv_skips_comments(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("# this is a comment\nREAL_KEY=value\n")
    monkeypatch.delenv("REAL_KEY", raising=False)

    original = os.path.join
    def patched_join(a, b):
        if b == ".env":
            return str(env_file)
        return original(a, b)

    monkeypatch.setattr(os.path, "join", patched_join)
    _load_dotenv()
    assert os.environ.get("REAL_KEY") == "value"


def test_load_dotenv_strips_quotes(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text('QUOTED_KEY="quoted_value"\n')
    monkeypatch.delenv("QUOTED_KEY", raising=False)

    original = os.path.join
    def patched_join(a, b):
        if b == ".env":
            return str(env_file)
        return original(a, b)

    monkeypatch.setattr(os.path, "join", patched_join)
    _load_dotenv()
    assert os.environ.get("QUOTED_KEY") == "quoted_value"


def test_load_dotenv_strips_single_quotes(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("SINGLE_KEY='singlequoted'\n")
    monkeypatch.delenv("SINGLE_KEY", raising=False)

    original = os.path.join
    def patched_join(a, b):
        if b == ".env":
            return str(env_file)
        return original(a, b)

    monkeypatch.setattr(os.path, "join", patched_join)
    _load_dotenv()
    assert os.environ.get("SINGLE_KEY") == "singlequoted"


def test_load_dotenv_skips_blank_lines(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("\n\nBLANK_SKIP_KEY=ok\n\n")
    monkeypatch.delenv("BLANK_SKIP_KEY", raising=False)

    original = os.path.join
    def patched_join(a, b):
        if b == ".env":
            return str(env_file)
        return original(a, b)

    monkeypatch.setattr(os.path, "join", patched_join)
    _load_dotenv()
    assert os.environ.get("BLANK_SKIP_KEY") == "ok"


def test_load_dotenv_missing_file_is_noop(tmp_path, monkeypatch):
    """No .env file should not raise."""
    missing = str(tmp_path / "does_not_exist" / ".env")

    original = os.path.join
    def patched_join(a, b):
        if b == ".env":
            return missing
        return original(a, b)

    monkeypatch.setattr(os.path, "join", patched_join)
    _load_dotenv()  # should not raise
