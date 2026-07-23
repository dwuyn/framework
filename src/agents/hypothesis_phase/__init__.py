"""
Compiled Phase 2 hypothesis subgraph.
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from src.state import PentestState

from .critic_agent import critic_agent_node, route_critic_agent
from .evidence_normalizer import evidence_normalizer_node
from .hypothesis_agent import hypothesis_agent_node
from .retrieval_agent import retrieval_agent_node
from .shared import VulnHypothesis


def build_hypothesis_phase_graph():
    graph = StateGraph(PentestState)
    graph.add_node("retrieval_agent", retrieval_agent_node)
    graph.add_node("evidence_normalizer", evidence_normalizer_node)
    graph.add_node("hypothesis_agent", hypothesis_agent_node)
    graph.add_node("critic_agent", critic_agent_node)

    graph.add_edge("retrieval_agent", "evidence_normalizer")
    graph.add_edge("evidence_normalizer", "hypothesis_agent")
    graph.add_edge("hypothesis_agent", "critic_agent")
    graph.add_conditional_edges(
        "critic_agent",
        route_critic_agent,
        {
            "hypothesis_agent": "hypothesis_agent",
            "end": END,
        },
    )
    graph.set_entry_point("retrieval_agent")
    return graph.compile()


__all__ = [
    "VulnHypothesis",
    "build_hypothesis_phase_graph",
    "critic_agent_node",
    "evidence_normalizer_node",
    "hypothesis_agent_node",
    "retrieval_agent_node",
]
