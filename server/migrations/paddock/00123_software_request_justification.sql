-- The user's justification of a software request (plan M13c decision 8, maintainer answer Q7, architect decision
-- A10-27, PDK-993). 00119 left the column out until the maintainer decided whether the text may be stored. It is
-- untrusted plain text: at most 500 characters without control characters except line breaks, which the worker checks
-- before it opens the request; the CHECK repeats the rule, so a row written outside the worker cannot hold more. It is
-- never copied into audit params, logs or notifications. The table's grants cover the new column. Forward-only: there
-- is no Down migration.
-- +goose Up
ALTER TABLE software_request
  ADD COLUMN justification text NOT NULL DEFAULT ''
    CHECK (char_length(justification) <= 500 AND justification !~ E'[\\x01-\\x09\\x0b-\\x1f\\x7f-\\x9f]');

-- +goose Down
