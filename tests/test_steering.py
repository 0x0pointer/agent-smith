"""
Unit tests for core.steering — SteeringQueue and SteeringDirective.
"""
import pytest
from core.steering import (
    SteeringQueue,
    RESUME_REQUIRED,
    CHAIN_REQUIRED,
    RESUME_TESTING,
)


@pytest.fixture
def queue(tmp_path, monkeypatch):
    """Isolated SteeringQueue backed by a temp file."""
    import core.steering as st_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    q = SteeringQueue()
    # Patch the module-level file reference used inside the queue instance
    import unittest.mock as mock
    with mock.patch.object(q, "_load", wraps=lambda: (
        __import__("json").loads(steering_file.read_text()).get("directives", [])
        if steering_file.exists() else []
    )):
        pass
    # Simpler: just monkeypatch _STEERING_FILE at class-method level
    # The queue reads _STEERING_FILE from the module global directly
    return q, steering_file


# Use a simpler fixture that just patches the module global
@pytest.fixture
def q(tmp_path, monkeypatch):
    import core.steering as st_mod
    steering_file = tmp_path / "steering_queue.json"
    monkeypatch.setattr(st_mod, "_STEERING_FILE", steering_file)
    return SteeringQueue()


class TestAddDirective:
    def test_creates_entry_in_file(self, q, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q2 = SteeringQueue()
        directive_id = q2.add_directive(
            code=CHAIN_REQUIRED,
            message="CHAIN NOW: /web-exploit",
            priority="high",
            skill="web-exploit",
            trigger="SKILL_CHAIN_GAP",
        )
        assert directive_id is not None
        assert directive_id.startswith("steer-")
        directives = q2._load()
        assert len(directives) == 1
        d = directives[0]
        assert d["code"] == CHAIN_REQUIRED
        assert d["skill"] == "web-exploit"
        assert d["status"] == "pending"
        assert d["priority"] == "high"
        assert d["trigger"] == "SKILL_CHAIN_GAP"

    def test_dedup_same_code_and_skill_pending(self, q, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q2 = SteeringQueue()
        id1 = q2.add_directive(code=CHAIN_REQUIRED, message="msg1", skill="web-exploit", trigger="X")
        id2 = q2.add_directive(code=CHAIN_REQUIRED, message="msg2", skill="web-exploit", trigger="X")
        assert id1 is not None
        assert id2 is None  # deduped
        assert len(q2._load()) == 1

    def test_dedup_only_applies_to_pending_or_injected(self, q, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q2 = SteeringQueue()
        id1 = q2.add_directive(code=CHAIN_REQUIRED, message="msg1", skill="web-exploit", trigger="X")
        q2.acknowledge(id1)
        id2 = q2.add_directive(code=CHAIN_REQUIRED, message="msg2", skill="web-exploit", trigger="X")
        assert id2 is not None  # acknowledged — can create new one
        assert len(q2._load()) == 2

    def test_different_skills_not_deduped(self, q, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q2 = SteeringQueue()
        id1 = q2.add_directive(code=CHAIN_REQUIRED, message="m1", skill="web-exploit", trigger="X")
        id2 = q2.add_directive(code=CHAIN_REQUIRED, message="m2", skill="credential-audit", trigger="X")
        assert id1 is not None
        assert id2 is not None
        assert len(q2._load()) == 2


class TestStatusTransitions:
    def test_mark_injected(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        did = q.add_directive(code=RESUME_REQUIRED, message="msg", trigger="TOOL_INACTIVITY")
        q.mark_injected(did)
        d = q._load()[0]
        assert d["status"] == "injected"
        assert d["injected_at"] is not None

    def test_acknowledge(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        did = q.add_directive(code=RESUME_REQUIRED, message="msg", trigger="TOOL_INACTIVITY")
        result = q.acknowledge(did, message="I will resume now")
        assert result is True
        d = q._load()[0]
        assert d["status"] == "acknowledged"
        assert d["ack_message"] == "I will resume now"
        assert d["acknowledged_at"] is not None

    def test_acknowledge_returns_false_for_unknown_id(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        result = q.acknowledge("steer-nonexistent")
        assert result is False

    def test_auto_satisfy(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        did = q.add_directive(code=CHAIN_REQUIRED, message="chain web-exploit", skill="web-exploit", trigger="GAP")
        satisfied = q.auto_satisfy("web-exploit")
        assert did in satisfied
        d = q._load()[0]
        assert d["status"] == "auto_satisfied"

    def test_auto_satisfy_does_not_affect_other_skills(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        d1 = q.add_directive(code=CHAIN_REQUIRED, message="chain web", skill="web-exploit", trigger="G")
        d2 = q.add_directive(code=CHAIN_REQUIRED, message="chain cred", skill="credential-audit", trigger="G")
        q.auto_satisfy("web-exploit")
        directives = {d["id"]: d for d in q._load()}
        assert directives[d1]["status"] == "auto_satisfied"
        assert directives[d2]["status"] == "pending"  # unaffected


class TestQueryMethods:
    def test_get_pending_returns_only_pending(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        d1 = q.add_directive(code=RESUME_REQUIRED, message="m1", trigger="T")
        d2 = q.add_directive(code=CHAIN_REQUIRED, message="m2", skill="web-exploit", trigger="T")
        q.mark_injected(d1)  # d1 now injected, not pending
        pending = q.get_pending()
        assert len(pending) == 1
        assert pending[0].id == d2

    def test_get_injected(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        d1 = q.add_directive(code=RESUME_REQUIRED, message="m1", trigger="T")
        q.mark_injected(d1)
        injected = q.get_injected()
        assert len(injected) == 1
        assert injected[0].id == d1

    def test_get_history_returns_all_newest_first(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        d1 = q.add_directive(code=RESUME_REQUIRED, message="first", trigger="T")
        d2 = q.add_directive(code=CHAIN_REQUIRED, message="second", skill="s", trigger="T")
        history = q.get_history()
        assert len(history) == 2
        assert history[0]["id"] == d2  # newest first
        assert history[1]["id"] == d1

    def test_acknowledge_latest_injected(self, tmp_path, monkeypatch):
        import core.steering as st_mod
        monkeypatch.setattr(st_mod, "_STEERING_FILE", tmp_path / "steering_queue.json")
        q = SteeringQueue()
        d1 = q.add_directive(code=RESUME_REQUIRED, message="m1", trigger="T")
        q.mark_injected(d1)
        acked_id = q.acknowledge_latest_injected(message="understood")
        assert acked_id == d1
        d = q._load()[0]
        assert d["status"] == "acknowledged"
        assert d["ack_message"] == "understood"
