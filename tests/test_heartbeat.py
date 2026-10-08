"""mcp_server._app.with_heartbeat — progress notifications keep long tools alive.

Claude Code aborts an MCP call that is silent for 300s; full-port naabu and the
spider died that way. The wrapper must emit progress while the work runs, return
the result unchanged, and propagate cancellation to the work."""
import asyncio

import pytest

from mcp_server._app import with_heartbeat


class _Ctx:
    def __init__(self, fail=False):
        self.beats = []
        self.fail = fail

    async def report_progress(self, progress, total=None, message=None):
        if self.fail:
            raise RuntimeError("no progress token")
        self.beats.append((progress, message))


async def _work(seconds, value="done"):
    await asyncio.sleep(seconds)
    return value


def test_emits_progress_while_running():
    ctx = _Ctx()
    out = asyncio.run(with_heartbeat(ctx, _work(0.35), "scan spider", interval=0.1))
    assert out == "done"
    assert len(ctx.beats) >= 2
    assert ctx.beats[0][0] == 1 and "scan spider still running" in ctx.beats[0][1]


def test_fast_call_sends_no_progress_and_none_ctx_passthrough():
    ctx = _Ctx()
    assert asyncio.run(with_heartbeat(ctx, _work(0), "kali", interval=1)) == "done"
    assert ctx.beats == []
    assert asyncio.run(with_heartbeat(None, _work(0, "x"), "kali")) == "x"


def test_progress_errors_never_fail_the_tool():
    assert asyncio.run(with_heartbeat(_Ctx(fail=True), _work(0.25), "k", interval=0.1)) == "done"


def test_exceptions_propagate():
    async def boom():
        raise ValueError("bad")
    with pytest.raises(ValueError):
        asyncio.run(with_heartbeat(_Ctx(), boom(), "k", interval=0.1))


def test_cancellation_cancels_work():
    state = {}

    async def long():
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    async def main():
        t = asyncio.ensure_future(with_heartbeat(_Ctx(), long(), "k", interval=0.05))
        await asyncio.sleep(0.12)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
        await asyncio.sleep(0)
    asyncio.run(main())
    assert state.get("cancelled")
