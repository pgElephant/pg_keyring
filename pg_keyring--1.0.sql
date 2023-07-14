/* contrib/pg_keyring/pg_keyring--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_keyring" to load this file. \quit

-- Register functions.
CREATE OR REPLACE FUNCTION keyring_key_generate(
  password text,
  protocol text,
  key_size integer
)
RETURNS TEXT AS
'MODULE_PATHNAME', 'keyring_key_generate'
LANGUAGE C STRICT;

CREATE OR REPLACE FUNCTION keyring_key_remove(
  password text
)
RETURNS TEXT AS
'MODULE_PATHNAME', 'keyring_key_remove'
LANGUAGE C STRICT;
