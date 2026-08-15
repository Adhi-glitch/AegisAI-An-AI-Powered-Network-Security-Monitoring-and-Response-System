"""
Knowledge graph stub. Intended to store entities and relationships discovered from alerts.
"""
from typing import Dict, Any


def add_entity(entity: Dict[str, Any]):
    # TODO: implement graph DB or RDF store integration
    return True


def query(q: str):
    return {"query": q, "results": []}
