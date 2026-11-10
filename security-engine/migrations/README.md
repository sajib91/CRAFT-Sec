# Database Migrations

Alembic revisions will live in this directory. No migrations exist yet because no database models have been implemented.

Rules:

- Migrations are explicit, reviewed, and never auto-generated silently in production.
- SQLite is the initial store; repository interfaces isolate it from domain logic.
- Large tensors, diffs, and exports belong in the artifact store, not in SQLite blobs.
