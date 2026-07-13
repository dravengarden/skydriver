PRAGMA foreign_keys = ON;

CREATE TABLE vfs_token_metadata (
    token_id TEXT PRIMARY KEY REFERENCES vfs_token_verifiers(id) ON DELETE CASCADE,
    label TEXT NOT NULL CHECK (
        length(CAST(label AS BLOB)) BETWEEN 1 AND 128
        AND trim(label) = label
    ),
    note TEXT NOT NULL DEFAULT '' CHECK (
        length(CAST(note AS BLOB)) <= 2048
        AND trim(note) = note
    ),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_by TEXT NOT NULL CHECK (updated_by = 'operator'),
    created_at INTEGER NOT NULL CHECK (created_at > 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at)
) STRICT;

INSERT INTO vfs_token_metadata (
    token_id, label, note, revision, updated_by, created_at, updated_at
)
SELECT token.id,
       CASE WHEN token.parent_token_id IS NULL
            THEN 'Bootstrap authority'
            ELSE 'Token ' || substr(token.id, 1, 8)
       END,
       '', 1, 'operator', token.created_at, token.created_at
FROM vfs_token_verifiers AS token;

CREATE TRIGGER create_default_vfs_token_metadata
AFTER INSERT ON vfs_token_verifiers
BEGIN
    INSERT INTO vfs_token_metadata (
        token_id, label, note, revision, updated_by, created_at, updated_at
    ) VALUES (
        NEW.id,
        CASE WHEN NEW.parent_token_id IS NULL
             THEN 'Bootstrap authority'
             ELSE 'Token ' || substr(NEW.id, 1, 8)
        END,
        '', 1, 'operator', NEW.created_at, NEW.created_at
    );
END;

CREATE TRIGGER validate_vfs_token_metadata_update
BEFORE UPDATE ON vfs_token_metadata
WHEN NEW.token_id != OLD.token_id
  OR NEW.created_at != OLD.created_at
  OR NEW.updated_by != 'operator'
  OR NEW.revision != OLD.revision + 1
  OR NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'token metadata mutation requires the next revision');
END;

CREATE TABLE management_mutation_receipts (
    operation_id TEXT PRIMARY KEY CHECK (
        length(operation_id) = 32
        AND operation_id NOT GLOB '*[^0-9a-f]*'
        AND operation_id != '00000000000000000000000000000000'
    ),
    operator_subject TEXT NOT NULL CHECK (operator_subject = 'operator'),
    kind TEXT NOT NULL CHECK (length(CAST(kind AS BLOB)) BETWEEN 1 AND 128),
    resource_id TEXT NOT NULL CHECK (length(CAST(resource_id AS BLOB)) BETWEEN 1 AND 256),
    idempotency_key TEXT NOT NULL CHECK (
        length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256
        AND trim(idempotency_key) = idempotency_key
    ),
    request_sha256 TEXT NOT NULL CHECK (
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    expected_revision INTEGER NOT NULL CHECK (expected_revision > 0),
    final_revision INTEGER NOT NULL CHECK (final_revision = expected_revision + 1),
    validation_digest TEXT NOT NULL CHECK (
        length(validation_digest) = 43
        AND validation_digest NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    result_json TEXT NOT NULL CHECK (json_valid(result_json)),
    committed_at INTEGER NOT NULL CHECK (committed_at > 0),
    UNIQUE (operator_subject, kind, idempotency_key)
) STRICT;

CREATE TRIGGER validate_token_annotation_receipt
BEFORE INSERT ON management_mutation_receipts
WHEN NEW.kind = 'token.annotation'
 AND NOT EXISTS (
    SELECT 1 FROM vfs_token_metadata
    WHERE token_id = NEW.resource_id
      AND revision = NEW.final_revision
      AND label = json_extract(NEW.result_json, '$.label')
      AND note = json_extract(NEW.result_json, '$.note')
 )
BEGIN
    SELECT RAISE(ABORT, 'token annotation receipt requires committed metadata');
END;
