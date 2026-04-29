"""PACT CLI: pact init, serve, discover, ask, receipts, identity."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pact.store import PACTStore


def _get_store() -> PACTStore:
    return PACTStore()


def cmd_init(args: argparse.Namespace) -> None:
    """Generate a new agent identity."""
    from pact.identity import Identity

    store = _get_store()
    name = args.name

    if store.has_agent(name):
        print(f"Agent '{name}' already exists.")
        print(f"  Keys: {store._agent_dir(name)}")
        return

    identity = Identity.create(name, store)
    print(f"Identity created.")
    print(f"  Agent:    {name}")
    print(f"  Agent ID: {identity.agent_id}")
    print(f"  Keys:     {store._agent_dir(name)}")
    print(f"  Next step: pact serve --agent {name}")


def cmd_serve(args: argparse.Namespace) -> None:
    """Start a PACT agent server."""
    from pact.agent import PACTAgent

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
            print(f"Specify one with: pact serve --agent <name>")
            sys.exit(1)

    if not store.has_agent(name):
        print(f"Agent '{name}' not found. Run: pact init {name}")
        sys.exit(1)

    caps = [c.strip() for c in args.capabilities.split(",")] if args.capabilities else []

    agent = PACTAgent(
        name=name,
        capabilities=caps,
        port=args.port,
        auto_grant=True,
    )

    # Register a default echo handler for any action in auto-grant mode
    @agent.handle("echo")
    def echo_handler(payload):
        return {"echo": payload}

    agent.serve(blocking=True)


def cmd_discover(args: argparse.Namespace) -> None:
    """Discover PACT agents on the local network."""
    from pact.transport.discovery import discover_agents

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
    from pact.agent import PACTAgent

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
            print(f"Multiple agents found. Specify with: pact ask --agent <name> ...")
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

    agent = PACTAgent(name=name, auto_grant=True)
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
            print(f"Multiple agents. Specify with: pact receipts --agent <name>")
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
            print(f"Multiple agents. Specify with: pact identity <name>")
            return

    if not store.has_agent(name):
        print(f"Agent '{name}' not found.")
        return

    doc = store.load_identity(name)
    print(json.dumps(doc, indent=2))


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
    }

    fn = commands.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
