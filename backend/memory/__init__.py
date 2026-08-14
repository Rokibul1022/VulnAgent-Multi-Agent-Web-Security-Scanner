"""Feedback + document memory store (agent.md §5.1).

SQLite holds the source-of-truth rows; Chroma holds embeddings for retrieval
into triage. All persistence is local under backend/storage/."""
