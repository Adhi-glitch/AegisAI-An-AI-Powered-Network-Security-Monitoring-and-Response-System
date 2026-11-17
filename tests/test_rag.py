from rag.knowledge_base import KnowledgeBase


def test_knowledge_base_returns_citations_for_known_topic():
    result = KnowledgeBase().answer("How should I handle a port scan?")
    assert result["grounded"] is True
    assert result["citations"][0]["document_id"] == "mitre-t1046"


def test_knowledge_base_is_honest_when_retrieval_is_weak():
    result = KnowledgeBase().answer("What is the weather tomorrow?")
    assert result["grounded"] is False
    assert "don't know" in result["answer"]