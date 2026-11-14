-- The backup leader epoch (plan M19 D5, RR-134): one row whose epoch the backup role increments right after it takes
-- its leader lock. Every write transaction of the leading role first reads the epoch under FOR SHARE and aborts when
-- it is no longer its own, so a process that lost the lock writes nothing once the next leader took over. FOR SHARE
-- needs the UPDATE grant, which the increment needs anyway. Platform data without organization_id, and therefore
-- without RLS (the pattern of 00100); state, never purged. Forward-only: there is no Down migration.
-- +goose Up
CREATE TABLE backup_leader (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  epoch bigint NOT NULL,
  holder text NOT NULL,
  acquired_at timestamptz NOT NULL
);
INSERT INTO backup_leader (epoch, holder, acquired_at) VALUES (0, '', now());

GRANT SELECT, UPDATE (epoch, holder, acquired_at) ON backup_leader TO paddock_backup;

-- +goose Down
