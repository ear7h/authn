PRAGMA foreign_keys = ON;

BEGIN EXCLUSIVE;

CREATE TABLE migrations (
	name text NOT NULL UNIQUE,
	created text NOT NULL DEFAULT (datetime('now', 'utc'))
);

INSERT INTO migrations (name) VALUES ('2021-09-17-init.sql');

CREATE TABLE users (
	name text PRIMARY KEY,
	pass_hash text NOT NULL,
	token_version integer NOT NULL DEFAULT 0
);

END;
