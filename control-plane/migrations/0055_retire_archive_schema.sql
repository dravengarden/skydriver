PRAGMA foreign_keys = ON;

-- Runtime and remote-data audits must both agree before the compatibility
-- archive schema can disappear. A non-empty table aborts this append-only
-- migration before any schema object is dropped.
DROP TABLE IF EXISTS legacy_archive_retirement_assertions;

CREATE TABLE legacy_archive_retirement_assertions (
    table_name TEXT PRIMARY KEY,
    row_count INTEGER NOT NULL CHECK (row_count = 0)
) STRICT;

INSERT INTO legacy_archive_retirement_assertions (table_name, row_count) VALUES
    ('audit_events', (SELECT COUNT(*) FROM audit_events)),
    ('blocks', (SELECT COUNT(*) FROM blocks)),
    ('chunks', (SELECT COUNT(*) FROM chunks)),
    ('client_namespace_permissions', (SELECT COUNT(*) FROM client_namespace_permissions)),
    ('client_token_verifiers', (SELECT COUNT(*) FROM client_token_verifiers)),
    ('clients', (SELECT COUNT(*) FROM clients)),
    ('compact_intents', (SELECT COUNT(*) FROM compact_intents)),
    ('copy_intents', (SELECT COUNT(*) FROM copy_intents)),
    ('copy_publication_intents', (SELECT COUNT(*) FROM copy_publication_intents)),
    ('copy_publication_locations', (SELECT COUNT(*) FROM copy_publication_locations)),
    ('extents', (SELECT COUNT(*) FROM extents)),
    ('gc_candidates', (SELECT COUNT(*) FROM gc_candidates)),
    ('gc_delete_tasks', (SELECT COUNT(*) FROM gc_delete_tasks)),
    ('gc_epochs', (SELECT COUNT(*) FROM gc_epochs)),
    ('gc_intents', (SELECT COUNT(*) FROM gc_intents)),
    ('gc_version_references', (SELECT COUNT(*) FROM gc_version_references)),
    ('import_intents', (SELECT COUNT(*) FROM import_intents)),
    ('integrity_findings', (SELECT COUNT(*) FROM integrity_findings)),
    ('integrity_observations', (SELECT COUNT(*) FROM integrity_observations)),
    ('inventory_completions', (SELECT COUNT(*) FROM inventory_completions)),
    ('inventory_intents', (SELECT COUNT(*) FROM inventory_intents)),
    ('inventory_report_objects', (SELECT COUNT(*) FROM inventory_report_objects)),
    ('inventory_report_pages', (SELECT COUNT(*) FROM inventory_report_pages)),
    ('leases', (SELECT COUNT(*) FROM leases)),
    ('locations', (SELECT COUNT(*) FROM locations)),
    ('logical_objects', (SELECT COUNT(*) FROM logical_objects)),
    ('move_delete_tasks', (SELECT COUNT(*) FROM move_delete_tasks)),
    ('move_intents', (SELECT COUNT(*) FROM move_intents)),
    ('move_sources', (SELECT COUNT(*) FROM move_sources)),
    ('move_tombstone_intents', (SELECT COUNT(*) FROM move_tombstone_intents)),
    ('namespaces', (SELECT COUNT(*) FROM namespaces)),
    ('object_blocks', (SELECT COUNT(*) FROM object_blocks)),
    ('object_versions', (SELECT COUNT(*) FROM object_versions)),
    ('objects', (SELECT COUNT(*) FROM objects)),
    ('operation_attempts', (SELECT COUNT(*) FROM operation_attempts)),
    ('operation_components', (SELECT COUNT(*) FROM operation_components)),
    ('operations', (SELECT COUNT(*) FROM operations)),
    ('pack_entries', (SELECT COUNT(*) FROM pack_entries)),
    ('packs', (SELECT COUNT(*) FROM packs)),
    ('publication_intents', (SELECT COUNT(*) FROM publication_intents)),
    ('quarantine_action_completions', (SELECT COUNT(*) FROM quarantine_action_completions)),
    ('quarantine_action_intents', (SELECT COUNT(*) FROM quarantine_action_intents)),
    ('quarantine_delete_tasks', (SELECT COUNT(*) FROM quarantine_delete_tasks)),
    ('quarantined_provider_objects', (SELECT COUNT(*) FROM quarantined_provider_objects)),
    ('reconcile_completions', (SELECT COUNT(*) FROM reconcile_completions)),
    ('reconcile_intents', (SELECT COUNT(*) FROM reconcile_intents)),
    ('reconcile_observations', (SELECT COUNT(*) FROM reconcile_observations)),
    ('recovery_manifests', (SELECT COUNT(*) FROM recovery_manifests)),
    ('repair_completion_objects', (SELECT COUNT(*) FROM repair_completion_objects)),
    ('repair_completions', (SELECT COUNT(*) FROM repair_completions)),
    ('repair_intents', (SELECT COUNT(*) FROM repair_intents)),
    ('repair_objects', (SELECT COUNT(*) FROM repair_objects)),
    ('repair_targets', (SELECT COUNT(*) FROM repair_targets)),
    ('replicas', (SELECT COUNT(*) FROM replicas)),
    ('restore_intents', (SELECT COUNT(*) FROM restore_intents)),
    ('telemetry_minute_buckets', (SELECT COUNT(*) FROM telemetry_minute_buckets)),
    ('telemetry_rollups', (SELECT COUNT(*) FROM telemetry_rollups)),
    ('transfer_jobs', (SELECT COUNT(*) FROM transfer_jobs)),
    ('verify_completions', (SELECT COUNT(*) FROM verify_completions)),
    ('verify_intents', (SELECT COUNT(*) FROM verify_intents)),
    ('version_chunks', (SELECT COUNT(*) FROM version_chunks)),
    ('version_packs', (SELECT COUNT(*) FROM version_packs)),
    ('vfs_principal_clients', (SELECT COUNT(*) FROM vfs_principal_clients));

DROP TABLE legacy_archive_retirement_assertions;

DROP VIEW gc_active_version_leases;
DROP VIEW gc_markable_locations;
DROP VIEW gc_protected_locations;
DROP VIEW inventory_missing_subjects;
DROP VIEW inventory_report_attempts;
DROP VIEW inventory_report_counts;
DROP VIEW safe_gc_delete_tasks;
DROP VIEW safe_move_delete_tasks;
DROP VIEW safe_quarantine_delete_tasks;

-- The tables are ordered from referencing leaves to referenced roots. This
-- keeps the migration valid even on SQLite builds that refuse to disable
-- foreign-key enforcement inside an imported transaction.
DROP TABLE audit_events;
DROP TABLE client_namespace_permissions;
DROP TABLE client_token_verifiers;
DROP TABLE compact_intents;
DROP TABLE copy_publication_locations;
DROP TABLE gc_candidates;
DROP TABLE gc_delete_tasks;
DROP TABLE gc_version_references;
DROP TABLE import_intents;
DROP TABLE integrity_findings;
DROP TABLE integrity_observations;
DROP TABLE inventory_completions;
DROP TABLE inventory_report_objects;
DROP TABLE leases;
DROP TABLE move_delete_tasks;
DROP TABLE move_sources;
DROP TABLE move_tombstone_intents;
DROP TABLE object_blocks;
DROP TABLE pack_entries;
DROP TABLE publication_intents;
DROP TABLE quarantine_action_completions;
DROP TABLE quarantine_delete_tasks;
DROP TABLE reconcile_completions;
DROP TABLE reconcile_intents;
DROP TABLE reconcile_observations;
DROP TABLE recovery_manifests;
DROP TABLE repair_completion_objects;
DROP TABLE repair_targets;
DROP TABLE replicas;
DROP TABLE restore_intents;
DROP TABLE telemetry_minute_buckets;
DROP TABLE telemetry_rollups;
DROP TABLE transfer_jobs;
DROP TABLE verify_completions;
DROP TABLE verify_intents;
DROP TABLE version_chunks;
DROP TABLE version_packs;
DROP TABLE vfs_principal_clients;
DROP TABLE copy_publication_intents;
DROP TABLE gc_epochs;
DROP TABLE gc_intents;
DROP TABLE inventory_report_pages;
DROP TABLE move_intents;
DROP TABLE logical_objects;
DROP TABLE quarantine_action_intents;
DROP TABLE repair_completions;
DROP TABLE locations;
DROP TABLE repair_objects;
DROP TABLE blocks;
DROP TABLE operation_attempts;
DROP TABLE chunks;
DROP TABLE inventory_intents;
DROP TABLE copy_intents;
DROP TABLE quarantined_provider_objects;
DROP TABLE extents;
DROP TABLE repair_intents;
DROP TABLE operation_components;
DROP TABLE packs;
DROP TABLE object_versions;
DROP TABLE operations;
DROP TABLE objects;
DROP TABLE clients;
DROP TABLE namespaces;

PRAGMA foreign_key_check;
PRAGMA optimize;
