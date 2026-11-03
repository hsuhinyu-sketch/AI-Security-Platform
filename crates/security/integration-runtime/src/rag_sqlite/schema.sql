CREATE TABLE asp_rag_meta (
 id INTEGER PRIMARY KEY CHECK(id=1), namespace TEXT NOT NULL, authority TEXT NOT NULL,
 max_documents INTEGER NOT NULL, max_contexts INTEGER NOT NULL, max_database_bytes INTEGER NOT NULL,
 highwater INTEGER NOT NULL CHECK(highwater>0)
) STRICT;
CREATE TABLE asp_rag_documents (
 tenant TEXT NOT NULL, corpus TEXT NOT NULL, document TEXT NOT NULL,
 metadata TEXT NOT NULL CHECK(length(CAST(metadata AS BLOB))<=1048576),
 PRIMARY KEY(tenant,corpus,document)
) STRICT;
CREATE TABLE asp_rag_contexts (
 id TEXT PRIMARY KEY NOT NULL, expires_ms INTEGER NOT NULL,
 snapshot TEXT NOT NULL CHECK(length(CAST(snapshot AS BLOB))<=1048576)
) STRICT;
PRAGMA application_id=1095979090;
PRAGMA user_version=1;
