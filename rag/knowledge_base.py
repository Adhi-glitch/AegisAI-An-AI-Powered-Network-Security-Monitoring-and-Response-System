"""Small offline-first security knowledge base.

The default implementation uses deterministic lexical retrieval so demos work
without downloading a model. Its document and result contracts are compatible
with a future embedding-backed index.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


@dataclass(frozen=True)
class KnowledgeDocument:
    document_id: str
    title: str
    text: str
    source: str
    chunk_id: int = 0


@dataclass(frozen=True)
class RetrievalResult:
    document: KnowledgeDocument
    score: float


DEFAULT_DOCUMENTS: tuple[KnowledgeDocument, ...] = (
    KnowledgeDocument(
        "mitre-t1046", "Network Service Scanning", "Port scanning discovers reachable services and hosts. Limit exposure, monitor connection bursts, and restrict management ports with firewall rules.", "MITRE ATT&CK T1046",
    ),
    KnowledgeDocument(
        "mitre-t1110", "Brute Force", "Brute force attempts repeatedly guess credentials. Apply MFA, rate-limit authentication, lock out abusive sources carefully, and review authentication logs.", "MITRE ATT&CK T1110",
    ),
    KnowledgeDocument(
        "mitre-t1498", "Network Denial of Service", "Denial of service exhausts bandwidth or service capacity. Rate-limit traffic, use upstream filtering, preserve allowlisted services, and capture evidence before containment.", "MITRE ATT&CK T1498",
    ),
    KnowledgeDocument(
        "aegis-response", "AegisAI response safety", "AegisAI defaults to dry-run. Allowlisted addresses must not be blocked. Automated blocks should have a TTL, an audit record, and an admin rollback path.", "AegisAI response policy",
    ),
)


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9]{3,}", text.lower())}


class KnowledgeBase:
    def __init__(self, documents: Iterable[KnowledgeDocument] = DEFAULT_DOCUMENTS):
        self.documents = tuple(documents)
        self._token_index = {doc.document_id + f"-{doc.chunk_id}": _tokens(doc.title + " " + doc.text) for doc in self.documents}

    def retrieve(self, query: str, limit: int = 5) -> list[RetrievalResult]:
        query_tokens = _tokens(query)
        if not query_tokens:
            return []
        results: list[RetrievalResult] = []
        for document in self.documents:
            overlap = query_tokens & self._token_index[document.document_id + f"-{document.chunk_id}"]
            if overlap:
                results.append(RetrievalResult(document, len(overlap) / len(query_tokens)))
        return sorted(results, key=lambda result: result.score, reverse=True)[:max(1, min(limit, 20))]

    def ingest(self, *, document_id: str, title: str, text: str, source: str, chunk_size: int = 800) -> int:
        """Chunk and add a local document; returns the number of chunks added."""
        if any(not value.strip() for value in (document_id, title, text, source)):
            raise ValueError("document_id, title, text, and source are required")
        if chunk_size < 100 or chunk_size > 10000:
            raise ValueError("chunk_size must be between 100 and 10000")
        chunks = [
            text[index:index + chunk_size].strip()
            for index in range(0, len(text), chunk_size)
            if text[index:index + chunk_size].strip()
        ]
        self.documents = tuple(document for document in self.documents if document.document_id != document_id)
        self.documents += tuple(KnowledgeDocument(document_id, title, chunk, source, index) for index, chunk in enumerate(chunks))
        self._token_index = {doc.document_id + f"-{doc.chunk_id}": _tokens(doc.title + " " + doc.text) for doc in self.documents}
        return len(chunks)

    def answer(self, query: str, limit: int = 3) -> dict:
        results = self.retrieve(query, limit)
        if not results or results[0].score < 0.15:
            return {"answer": "I don't know based on the indexed security knowledge.", "grounded": False, "citations": [], "results": []}
        citations = [
            {"document_id": result.document.document_id, "title": result.document.title, "source": result.document.source, "score": round(result.score, 3)}
            for result in results
        ]
        answer = " ".join(result.document.text for result in results)
        return {"answer": answer, "grounded": True, "citations": citations, "results": citations}


knowledge_base = KnowledgeBase()