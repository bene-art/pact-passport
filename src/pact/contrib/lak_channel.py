"""PACTChannel: bridge between local-agent-kit and PACT protocol.

Makes any local-agent-kit agent PACT-addressable with 3 lines:

    from pact import PACTAgent
    from pact.contrib.lak_channel import PACTChannel

    pact = PACTAgent("alice", capabilities=["ask_question"])
    channel = PACTChannel(pact)
    agent = Agent.from_directory("./my-agent", channel=channel)
    asyncio.run(agent.run())

Incoming PACT REQ messages with intent:"task" are converted to LAK Messages
and yielded from listen(). The agent's LLM response is sent back as a PACT RES.

Requires: pip install pact-protocol[lak]

**Known limitations** (will be addressed in future v0.x releases):

- The bridge replaces the dispatch entry point, which means PACT-side
  validation (sender verification, capability check, holder proof,
  rate limit) is **bypassed** for task intents. Callers are presumed
  trusted by the surrounding LAN setup. Do not expose a LAK-bridged
  agent to untrusted networks until validation is layered in.
- Bridged dispatch uses a sync polling wait (100ms × 300 iterations)
  for the LAK response. This blocks an HTTP handler thread per
  outstanding LAK call. Use the async server (`AsyncPACTServer`) if
  you need higher concurrency.
- The new v0.2-v0.5 message fields (`identity_doc`, `cap_envelope`,
  `stream`) are not propagated to the LAK side. LAK responses are
  one-shot only; no streaming RES_CHUNK support.
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator

from pact.agent import PACTAgent
from pact.message import PACTMessage, build_res

logger = logging.getLogger(__name__)


class _LAKMessage:
    """Minimal LAK-compatible message (matches local_agent_kit.channels.base.Message)."""
    def __init__(self, text: str, thread_id: str = ""):
        self.text = text
        self.thread_id = thread_id


class PACTChannel:
    """Bridge PACT protocol into local-agent-kit's Channel interface.

    Implements the Channel protocol:
      - async listen() -> yields Messages
      - async send(text, thread_id) -> bool
      - async start() / stop()

    If local-agent-kit is installed, this can be used directly as a Channel.
    If not, it still works as a standalone bridge with the same interface.
    """

    def __init__(self, pact_agent: PACTAgent):
        self._pact = pact_agent
        self._queue: asyncio.Queue[tuple[_LAKMessage, PACTMessage]] = asyncio.Queue()
        self._pending_req: PACTMessage | None = None
        self._original_dispatch = None

    async def start(self) -> None:
        """Start the PACT server in the background."""
        # Wrap the agent's dispatch to intercept task REQs
        identity = self._pact._ensure_identity()
        self._original_dispatch = self._pact._dispatch

        def bridged_dispatch(body: dict) -> dict:
            msg = PACTMessage.from_dict(body)

            # Non-task intents pass through to normal PACT handling
            if msg.intent != "task":
                return self._original_dispatch(body)

            # Task intents get queued for the LAK agent
            payload_text = msg.payload.get("text", msg.payload.get("query", str(msg.payload)))
            lak_msg = _LAKMessage(text=payload_text, thread_id=msg.id)

            # Put in queue (blocking from sync context)
            try:
                self._queue.put_nowait((lak_msg, msg))
            except asyncio.QueueFull:
                return build_res(
                    identity._private_key, identity.agent_id, msg,
                    status="error",
                    fault={"code": "overloaded", "detail": "Agent queue is full"},
                ).to_dict()

            # Wait for the LAK agent to process and send() the response
            # Return a placeholder — the actual response is sent via send()
            # For sync HTTP, we need to block until response is ready
            import time
            for _ in range(300):  # 30 second timeout
                if hasattr(self, '_last_response') and self._last_response_for == msg.id:
                    resp = self._last_response
                    del self._last_response
                    del self._last_response_for
                    return resp
                time.sleep(0.1)

            return build_res(
                identity._private_key, identity.agent_id, msg,
                status="error",
                fault={"code": "timeout", "detail": "LAK agent did not respond in time"},
            ).to_dict()

        # Replace the agent's dispatch with our bridged version.
        # PACTServer reads this attribute when starting (agent.py:serve);
        # setting it here means the server picks up bridged_dispatch.
        # Pre-v0.5.1 this assigned to a non-existent _server_dispatch,
        # silently no-op'ing the bridge.
        self._pact._dispatch = bridged_dispatch
        self._pact.serve(blocking=False)

    async def stop(self) -> None:
        """Stop the PACT server."""
        self._pact.stop()

    async def listen(self) -> AsyncIterator[_LAKMessage]:
        """Yield incoming PACT task requests as LAK Messages."""
        while True:
            lak_msg, pact_req = await self._queue.get()
            self._pending_req = pact_req
            yield lak_msg

    async def send(self, text: str, thread_id: str = "") -> bool:
        """Send the LAK agent's response back as a PACT RES."""
        if not self._pending_req:
            logger.warning("send() called with no pending PACT request")
            return False

        identity = self._pact._ensure_identity()
        res = build_res(
            identity._private_key,
            identity.agent_id,
            self._pending_req,
            payload={"text": text},
        )

        # Store response for the bridged dispatch to pick up
        self._last_response = res.to_dict()
        self._last_response_for = self._pending_req.id
        self._pending_req = None

        return True
