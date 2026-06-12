"""PACT CLI: pact init, serve, discover, ask, receipts, identity."""

from __future__ import annotations

import argparse
import json
import sys

from pact_passport.store import PACTStore


def _get_store() -> PACTStore:
    return PACTStore()


def cmd_init(args: argparse.Namespace) -> None:
    """Generate a new agent identity."""
    from pact_passport.identity import Identity

    store = _get_store()
    name = args.name

    if store.has_agent(name):
        print(f"Agent '{name}' already exists.")
        print(f"  Keys: {store._agent_dir(name)}")
        return

    identity = Identity.create(name, store)
    print("Identity created.")
    print(f"  Agent:    {name}")
    print(f"  Agent ID: {identity.agent_id}")
    print(f"  Keys:     {store._agent_dir(name)}")
    print(f"  Next step: pact serve --agent {name}")


def cmd_serve(args: argparse.Namespace) -> None:
    """Start a PACT agent server."""
    from pact_passport.agent import PACTAgent

    store = _get_store()
    name = args.agent

    if not name:
        agents = store.list_agents()
        if len(agents) == 1:
            name = agents[0]
        elif not agents:
            print("No agents found. Run: pact init <name>")
            sys.exit(1)
        else:
            print(f"Multiple agents found: {', '.join(agents)}")
            print("Specify one with: pact serve --agent <name>")
            sys.exit(1)

    if not store.has_agent(name):
        print(f"Agent '{name}' not found. Run: pact init {name}")
        sys.exit(1)

    caps = [c.strip() for c in args.capabilities.split(",")] if args.capabilities else []

    agent = PACTAgent(
        name=name,
        capabilities=caps,
        port=args.port,
    )

    # Register a default echo handler for any action
    @agent.handle("echo")
    def echo_handler(payload):
        return {"echo": payload}

    agent.serve(blocking=True)


def cmd_discover(args: argparse.Namespace) -> None:
    """Discover PACT agents on the local network."""
    from pact_passport.transport.discovery import discover_agents

    agents = discover_agents(timeout=args.timeout)

    if not agents:
        print("No PACT agents found on the local network.")
        print("Hint: Is another agent running? Try: pact serve")
        return

    # Table header
    print(f"{'NAME':<15} {'AGENT ID':<20} {'CAPABILITIES':<30} {'ENDPOINT'}")
    print(f"{'-'*15} {'-'*20} {'-'*30} {'-'*25}")
    for a in agents:
        aid = a["agent_id"][:18] + ".." if len(a["agent_id"]) > 20 else a["agent_id"]
        caps = ", ".join(a["capabilities"])
        endpoint = f"{a['host']}:{a['port']}"
        print(f"{a['name']:<15} {aid:<20} {caps:<30} {endpoint}")


def cmd_ask(args: argparse.Namespace) -> None:
    """Send a task REQ to another agent."""
    from pact_passport.agent import PACTAgent

    store = _get_store()
    name = args.agent

    if not name:
        agents = store.list_agents()
        if len(agents) == 1:
            name = agents[0]
        elif not agents:
            print("No local agents found. Run: pact init <name>")
            sys.exit(1)
        else:
            print("Multiple agents found. Specify with: pact ask --agent <name> ...")
            sys.exit(1)

    if not store.has_agent(name):
        print(f"Agent '{name}' not found. Run: pact init {name}")
        sys.exit(1)

    # Parse payload
    payload = {}
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            print(f"Invalid JSON payload: {args.payload}")
            sys.exit(1)

    agent = PACTAgent(name=name)
    result = agent.ask(
        target=args.target,
        action=args.action,
        payload=payload,
        deadline_seconds=args.deadline,
    )

    if result.get("status") == "error":
        fault = result.get("fault", {})
        print(f"Error: {fault.get('code', 'unknown')} — {fault.get('detail', '')}")
        sys.exit(1)

    # Print the payload from the response
    res_payload = result.get("payload", result)
    print(json.dumps(res_payload, indent=2))


def cmd_receipts(args: argparse.Namespace) -> None:
    """List audit receipts."""
    store = _get_store()
    name = args.agent

    if not name:
        agents = store.list_agents()
        if len(agents) == 1:
            name = agents[0]
        elif not agents:
            print("No agents found.")
            return
        else:
            print("Multiple agents. Specify with: pact receipts --agent <name>")
            return

    receipts = store.list_receipts(name)
    if not receipts:
        print(f"No receipts for agent '{name}'.")
        return

    print(f"{'TIMESTAMP':<28} {'TASK REF':<12} {'OUTCOME'}")
    print(f"{'-'*28} {'-'*12} {'-'*12}")
    for r in receipts:
        ts = r.get("timestamp", "?")[:26]
        ref = r.get("task_ref", "?")[:10]
        outcome = r.get("outcome", "?")
        print(f"{ts:<28} {ref:<12} {outcome}")


def cmd_identity(args: argparse.Namespace) -> None:
    """Print an agent's public identity document."""
    store = _get_store()
    name = args.name

    if not name:
        agents = store.list_agents()
        if len(agents) == 1:
            name = agents[0]
        elif not agents:
            print("No agents found.")
            return
        else:
            print("Multiple agents. Specify with: pact identity <name>")
            return

    if not store.has_agent(name):
        print(f"Agent '{name}' not found.")
        return

    doc = store.load_identity(name)
    print(json.dumps(doc, indent=2))


def cmd_grant(args: argparse.Namespace) -> None:
    """Issue a capability token to another agent."""
    from pact_passport.agent import PACTAgent
    from pact_passport.capability import Caveat

    store = _get_store()
    name = _resolve_agent_name(store, args.agent)
    if not name:
        return

    caveats = []
    if args.expires:
        caveats.append(Caveat("expires", args.expires))
    if args.max_invocations:
        caveats.append(Caveat("max_invocations", args.max_invocations))
    if args.no_delegation:
        caveats.append(Caveat("no_further_delegation", True, terminal=True))

    agent = PACTAgent(name=name)
    token = agent.grant(args.holder, args.action, caveats=caveats or None)

    print("Capability issued.")
    print(f"  cap_id:  {token.cap_id}")
    print(f"  action:  {token.action}")
    print(f"  holder:  {token.holder}")
    if caveats:
        for c in caveats:
            print(f"  caveat:  {c.restrict} = {c.value}")
    print("\nShare the cap_id with the holder agent.")


def cmd_revoke(args: argparse.Namespace) -> None:
    """Revoke a capability token."""
    from pact_passport.agent import PACTAgent

    store = _get_store()
    name = _resolve_agent_name(store, args.agent)
    if not name:
        return

    agent = PACTAgent(name=name)
    if agent.revoke(args.cap_id):
        print(f"Capability {args.cap_id} revoked.")
    else:
        print(f"Capability {args.cap_id} not found.")


def cmd_caps(args: argparse.Namespace) -> None:
    """List issued capability tokens."""
    store = _get_store()
    name = _resolve_agent_name(store, args.agent)
    if not name:
        return

    caps = store.list_capabilities(name)
    if not caps:
        print(f"No capabilities for agent '{name}'.")
        return

    print(f"{'CAP ID':<20} {'ACTION':<20} {'HOLDER':<25} {'REVOKED'}")
    print(f"{'-'*20} {'-'*20} {'-'*25} {'-'*8}")
    for c in caps:
        cid = c.get("cap_id", "?")[:18]
        action = c.get("action", "?")
        holder = c.get("holder", "?")[:23]
        revoked = "YES" if c.get("revoked") else ""
        print(f"{cid:<20} {action:<20} {holder:<25} {revoked}")


def cmd_trace(args: argparse.Namespace) -> None:
    """Trace the causal chain for a message."""
    from pact_passport.agent import PACTAgent

    store = _get_store()
    name = _resolve_agent_name(store, args.agent)
    if not name:
        return

    agent = PACTAgent(name=name)
    chain = agent.get_causal_chain(args.msg_id)
    if not chain:
        print(f"No messages found for ID: {args.msg_id}")
        return

    print(f"Causal chain ({len(chain)} messages):\n")
    for i, msg in enumerate(chain):
        prefix = "  " if i > 0 else ""
        mtype = msg.get("type", "?")
        mid = msg.get("id", "?")[:20]
        intent = msg.get("intent", "")
        status = msg.get("status", "")
        refs = msg.get("refs", [])
        print(f"{prefix}[{mtype}] {mid}...")
        if intent:
            print(f"{prefix}  intent: {intent}")
        if status:
            print(f"{prefix}  status: {status}")
        if refs:
            print(f"{prefix}  refs:   {', '.join(r[:12] + '...' for r in refs)}")
        print()


def cmd_rotate(args: argparse.Namespace) -> None:
    """Rotate an agent's keys using pre-rotation."""
    from pact_passport.identity import Identity

    store = _get_store()
    name = _resolve_agent_name(store, args.name)
    if not name:
        return

    identity = Identity.load(name, store)
    old_pub = identity.public_key_b64()[:20]

    try:
        event = identity.rotate()
        new_pub = identity.public_key_b64()[:20]
        print("Key rotation complete.")
        print(f"  Agent:    {name}")
        print(f"  Agent ID: {identity.agent_id}  (unchanged)")
        print(f"  Old key:  {old_pub}...")
        print(f"  New key:  {new_pub}...")
        print(f"  Sequence: {event['sequence']}")
        print("  Next key committed (pre-rotation)")
    except ValueError as e:
        print(f"Rotation failed: {e}")
        sys.exit(1)


def cmd_doctor(args: argparse.Namespace) -> None:
    """Validate agent setup: keys, event log, permissions."""
    from pact_passport.identity import Identity

    store = _get_store()
    name = _resolve_agent_name(store, args.name)
    if not name:
        return

    print(f"Checking agent '{name}'...\n")
    issues = []
    passes = []

    # Check key files exist
    agent_dir = store._agent_dir(name)
    priv_path = agent_dir / "private_key.bin"
    next_path = agent_dir / "next_private_key.bin"

    if priv_path.exists():
        passes.append("Private key file exists")
        mode = priv_path.stat().st_mode & 0o777
        if mode == 0o600:
            passes.append(f"Private key permissions: {oct(mode)} (correct)")
        else:
            issues.append(f"Private key permissions: {oct(mode)} (should be 0o600)")
            print(f"  Fix: chmod 600 {priv_path}")
    else:
        issues.append("Private key file missing")

    if next_path.exists():
        passes.append("Next (pre-rotation) key file exists")
        mode = next_path.stat().st_mode & 0o777
        if mode == 0o600:
            passes.append(f"Next key permissions: {oct(mode)} (correct)")
        else:
            issues.append(f"Next key permissions: {oct(mode)} (should be 0o600)")
    else:
        issues.append("Next (pre-rotation) key file missing")

    # Check identity document
    id_path = agent_dir / "identity.json"
    if id_path.exists():
        passes.append("Identity document exists")
    else:
        issues.append("Identity document missing")

    # Check event log
    events = store.load_event_log(name)
    if events:
        passes.append(f"Event log: {len(events)} event(s)")

        # Verify event log integrity
        identity = Identity.load(name, store)
        log_errors = identity.verify_event_log()
        if not log_errors:
            passes.append("Event log integrity: all signatures valid")
            passes.append("Event log chain: all digests match")
        else:
            for err in log_errors:
                issues.append(f"Event log: {err}")
    else:
        issues.append("Event log is empty")

    # Check store structure
    for subdir in ["capabilities", "receipts", "messages"]:
        d = agent_dir / subdir
        if d.exists():
            count = len(list(d.glob("*.json")))
            passes.append(f"{subdir}/: {count} file(s)")

    # Check peers
    peers = store.list_peers()
    passes.append(f"Known peers: {len(peers)}")

    # Print results
    for p in passes:
        print(f"  \033[32m✓\033[0m {p}")
    for i in issues:
        print(f"  \033[31m✗\033[0m {i}")

    print()
    if issues:
        print(f"\033[31m{len(issues)} issue(s) found.\033[0m")
        sys.exit(1)
    else:
        print("\033[32mAll checks passed.\033[0m")


def _resolve_agent_name(store: PACTStore, name: str | None) -> str | None:
    """Helper to resolve a single agent name from store."""
    if not name:
        agents = store.list_agents()
        if len(agents) == 1:
            return agents[0]
        elif not agents:
            print("No agents found. Run: pact init <name>")
            return None
        else:
            print(f"Multiple agents: {', '.join(agents)}. Use --agent <name>")
            return None
    if not store.has_agent(name):
        print(f"Agent '{name}' not found. Run: pact init {name}")
        return None
    return name


def cmd_peers(args: argparse.Namespace) -> None:
    """List known peers."""
    store = _get_store()
    peers = store.list_peers()
    if not peers:
        print("No known peers.")
        return

    print(f"{'AGENT ID':<25} {'ALG':<10} {'PUBLIC KEY (prefix)'}")
    print(f"{'-'*25} {'-'*10} {'-'*25}")
    for p in peers:
        aid = p.get("agent_id", "?")[:23]
        alg = p.get("alg", "?")
        pk = p.get("public_key", "?")[:23]
        print(f"{aid:<25} {alg:<10} {pk}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pact",
        description="PACT — Protocol for Agent Capability and Trust",
    )
    sub = parser.add_subparsers(dest="command")

    # pact init
    p_init = sub.add_parser("init", help="Create a new agent identity")
    p_init.add_argument("name", help="Agent name")

    # pact serve
    p_serve = sub.add_parser("serve", help="Start the PACT server")
    p_serve.add_argument("--agent", "-a", default=None, help="Agent name")
    p_serve.add_argument("--port", "-p", type=int, default=0, help="Port (0=auto)")
    p_serve.add_argument("--capabilities", "-c", default="", help="Comma-separated capabilities")

    # pact discover
    p_discover = sub.add_parser("discover", help="Find agents on the local network")
    p_discover.add_argument("--timeout", "-t", type=float, default=3.0, help="Discovery timeout")

    # pact ask
    p_ask = sub.add_parser("ask", help="Send a task to another agent")
    p_ask.add_argument("target", help="Target agent name or ID prefix")
    p_ask.add_argument("action", help="Capability action to request")
    p_ask.add_argument("payload", nargs="?", default=None, help="JSON payload")
    p_ask.add_argument("--agent", "-a", default=None, help="Local agent name")
    p_ask.add_argument("--deadline", "-d", type=int, default=30, help="Deadline in seconds")

    # pact receipts
    p_receipts = sub.add_parser("receipts", help="List audit receipts")
    p_receipts.add_argument("--agent", "-a", default=None, help="Agent name")

    # pact identity
    p_identity = sub.add_parser("identity", help="Show agent identity document")
    p_identity.add_argument("name", nargs="?", default=None, help="Agent name")

    # pact peers
    sub.add_parser("peers", help="List known peers")

    # pact rotate
    p_rotate = sub.add_parser("rotate", help="Rotate agent keys (pre-rotation)")
    p_rotate.add_argument("name", nargs="?", default=None, help="Agent name")

    # pact doctor
    p_doctor = sub.add_parser("doctor", help="Validate agent setup")
    p_doctor.add_argument("name", nargs="?", default=None, help="Agent name")

    # pact grant
    p_grant = sub.add_parser("grant", help="Issue a capability token")
    p_grant.add_argument("holder", help="Holder agent_id")
    p_grant.add_argument("action", help="Capability action")
    p_grant.add_argument("--agent", "-a", default=None, help="Issuer agent name")
    p_grant.add_argument("--expires", default=None, help="Expiry (ISO 8601)")
    p_grant.add_argument("--max-invocations", type=int, default=None, help="Max invocations")
    p_grant.add_argument("--no-delegation", action="store_true", help="Prevent further delegation")

    # pact revoke
    p_revoke = sub.add_parser("revoke", help="Revoke a capability token")
    p_revoke.add_argument("cap_id", help="Capability ID to revoke")
    p_revoke.add_argument("--agent", "-a", default=None, help="Agent name")

    # pact caps
    p_caps = sub.add_parser("caps", help="List issued capabilities")
    p_caps.add_argument("--agent", "-a", default=None, help="Agent name")

    # pact trace
    p_trace = sub.add_parser("trace", help="Trace causal chain for a message")
    p_trace.add_argument("msg_id", help="Message ID to trace")
    p_trace.add_argument("--agent", "-a", default=None, help="Agent name")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print("\nQuick start:")
        print("  pact init alice              # create identity")
        print("  pact serve --agent alice     # start server")
        print("  pact discover                # find agents")
        print("  pact ask alice echo '{}'     # send a task")
        sys.exit(0)

    commands = {
        "init": cmd_init,
        "serve": cmd_serve,
        "discover": cmd_discover,
        "ask": cmd_ask,
        "receipts": cmd_receipts,
        "identity": cmd_identity,
        "peers": cmd_peers,
        "rotate": cmd_rotate,
        "doctor": cmd_doctor,
        "grant": cmd_grant,
        "revoke": cmd_revoke,
        "caps": cmd_caps,
        "trace": cmd_trace,
    }

    fn = commands.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
