"""Agent identity graph and agent behaviour graph (sections 5 and 8).

Two graphs share one storage primitive:

* the **identity graph** holds organisations, owners, runtimes, agents, tools,
  datasets, endpoints and the relationships between them (OWNS, RUNS,
  AUTHORIZES, DELEGATES_TO, CALLS, READS, WRITES, COMMUNICATES_WITH,
  CREATED_BY, REVOKED_BY);
* the **behaviour graph** holds agent -> task -> (tool | data | endpoint)
  sequences, so analysis operates on chains rather than isolated events.

Both are queryable: neighbours, paths, reachability, delegation closure and
blast radius.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Node:
    node_id: str
    node_type: str
    attributes: tuple[tuple[str, str], ...] = ()

    def attrs(self) -> dict:
        return dict(self.attributes)


@dataclass(frozen=True)
class Edge:
    source: str
    relation: str
    target: str
    at: int = 0
    attributes: tuple[tuple[str, str], ...] = ()

    def attrs(self) -> dict:
        return dict(self.attributes)


class Graph:
    def __init__(self, name: str) -> None:
        self.name = name
        self._nodes: dict[str, Node] = {}
        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)
        self._edges: list[Edge] = []

    # -- mutation ----------------------------------------------------------
    def add_node(self, node_id: str, node_type: str, **attributes) -> Node:
        node = Node(node_id, node_type, tuple(sorted((k, str(v)) for k, v in attributes.items())))
        self._nodes[node_id] = node
        return node

    def add_edge(self, source: str, relation: str, target: str, *, at: int = 0, **attributes) -> Edge:
        edge = Edge(source, relation, target, at, tuple(sorted((k, str(v)) for k, v in attributes.items())))
        self._edges.append(edge)
        self._out[source].append(edge)
        self._in[target].append(edge)
        return edge

    # -- access ------------------------------------------------------------
    def node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def nodes(self, node_type: str | None = None) -> list[Node]:
        values = list(self._nodes.values())
        if node_type:
            values = [n for n in values if n.node_type == node_type]
        return sorted(values, key=lambda n: n.node_id)

    def edges(self, relation: str | None = None) -> list[Edge]:
        if relation is None:
            return list(self._edges)
        return [e for e in self._edges if e.relation == relation]

    def out_edges(self, node_id: str, relation: str | None = None) -> list[Edge]:
        edges = self._out.get(node_id, [])
        return [e for e in edges if relation is None or e.relation == relation]

    def in_edges(self, node_id: str, relation: str | None = None) -> list[Edge]:
        edges = self._in.get(node_id, [])
        return [e for e in edges if relation is None or e.relation == relation]

    def neighbours(self, node_id: str, relation: str | None = None) -> list[str]:
        return sorted({e.target for e in self.out_edges(node_id, relation)})

    # -- analysis ----------------------------------------------------------
    def paths(self, source: str, target: str, max_depth: int = 4) -> list[list[str]]:
        results: list[list[str]] = []
        queue: deque[list[str]] = deque([[source]])
        while queue:
            path = queue.popleft()
            if len(path) - 1 > max_depth:
                continue
            current = path[-1]
            if current == target and len(path) > 1:
                results.append(path)
                continue
            for edge in self.out_edges(current):
                if edge.target in path:
                    continue
                queue.append(path + [edge.target])
        return results

    def reachable(self, source: str, relation: str | None = None, max_depth: int = 6) -> set[str]:
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(source, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbour in self.neighbours(current, relation):
                if neighbour not in seen:
                    seen.add(neighbour)
                    queue.append((neighbour, depth + 1))
        return seen

    def blast_radius(self, agent_id: str) -> dict:
        """What an agent can reach directly or by delegation."""
        delegated = self.reachable(agent_id, "DELEGATES_TO")
        touched: set[str] = set()
        for actor in {agent_id} | delegated:
            touched |= {e.target for e in self.out_edges(actor) if e.relation in {"CALLS", "READS", "WRITES", "COMMUNICATES_WITH"}}
        return {
            "agent": agent_id,
            "delegated_agents": sorted(delegated),
            "resources": sorted(touched),
            "degree": len(self.out_edges(agent_id)),
        }

    def summary(self) -> dict:
        by_type: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            by_type[node.node_type] += 1
        by_relation: dict[str, int] = defaultdict(int)
        for edge in self._edges:
            by_relation[edge.relation] += 1
        return {"name": self.name, "nodes": dict(by_type), "edges": dict(by_relation)}


class AgentIdentityGraph(Graph):
    """Section 5 graph: who owns, runs, authorizes and delegates to whom."""

    def __init__(self) -> None:
        super().__init__("agent-identity-graph")

    def ingest_principal(self, principal) -> None:
        self.add_node(
            principal.principal_id,
            principal.kind.value,
            display_name=principal.display_name,
            runtime=principal.runtime or "",
            model=principal.model or "",
        )
        if principal.org_id:
            self.add_node(principal.org_id, "ORGANIZATION")
            self.add_edge(principal.org_id, "OWNS", principal.principal_id)
        if principal.owner_id:
            self.add_node(principal.owner_id, "OWNER")
            self.add_edge(principal.owner_id, "OWNS", principal.principal_id)
        if principal.runtime:
            self.add_node(principal.runtime, "RUNTIME")
            self.add_edge(principal.runtime, "RUNS", principal.principal_id)
        if principal.created_by:
            self.add_edge(principal.principal_id, "CREATED_BY", principal.created_by)

    def ingest_grant(self, grant) -> None:
        capability_node = f"capability:{grant.capability}"
        self.add_node(capability_node, "CAPABILITY")
        self.add_edge(grant.granted_by, "AUTHORIZES", grant.subject_id, capability=grant.capability, grant_id=grant.grant_id)
        self.add_edge(grant.subject_id, "HOLDS", capability_node, grant_id=grant.grant_id)

    def ingest_revocation(self, revocation) -> None:
        self.add_edge(revocation.subject_id, "REVOKED_BY", revocation.revoked_by, capability=revocation.capability)

    def ingest_delegation(self, delegator_id: str, delegatee_id: str, capabilities: Iterable[str], at: int = 0) -> None:
        self.add_edge(delegator_id, "DELEGATES_TO", delegatee_id, at=at, capabilities=",".join(sorted(capabilities)))

    def delegation_chains(self, agent_id: str) -> list[list[str]]:
        chains: list[list[str]] = []

        def walk(path: list[str]) -> None:
            children = self.neighbours(path[-1], "DELEGATES_TO")
            if not children:
                if len(path) > 1:
                    chains.append(path)
                return
            for child in children:
                if child in path:
                    chains.append(path + [child])  # cycle, recorded explicitly
                    continue
                walk(path + [child])

        walk([agent_id])
        return chains


class BehaviorGraph(Graph):
    """Section 8 graph: agent -> task -> tool/data/endpoint, plus delegation."""

    def __init__(self) -> None:
        super().__init__("agent-behavior-graph")

    def ingest_event(self, event) -> None:
        self.add_node(event.agent_id, "AGENT")
        task_node = event.task_id or f"{event.agent_id}:adhoc"
        self.add_node(task_node, "TASK")
        self.add_edge(event.agent_id, "EXECUTES", task_node, at=event.at)
        if event.tool:
            self.add_node(event.tool, "TOOL")
            self.add_edge(task_node, "CALLS", event.tool, at=event.at, decision=event.decision)
        if event.dataset:
            self.add_node(event.dataset, "DATA")
            relation = "WRITES" if "write" in event.capability else "READS"
            self.add_edge(task_node, relation, event.dataset, at=event.at, decision=event.decision)
        if event.endpoint:
            self.add_node(event.endpoint, "ENDPOINT")
            self.add_edge(task_node, "COMMUNICATES_WITH", event.endpoint, at=event.at, decision=event.decision)
        if event.target_agent:
            self.add_node(event.target_agent, "AGENT")
            relation = "DELEGATES_TO" if event.capability == "agent.delegate" else "COMMUNICATES_WITH"
            self.add_edge(event.agent_id, relation, event.target_agent, at=event.at, decision=event.decision)

    def chain_for(self, agent_id: str, window: int = 10) -> list[str]:
        """Ordered resource chain for an agent, newest last."""
        chain: list[str] = []
        for edge in self._edges[-window * 4 :]:
            if edge.source == agent_id or edge.source.startswith(f"{agent_id}:"):
                chain.append(f"{edge.relation}:{edge.target}")
        return chain[-window:]
