package backuprole

import "github.com/prometheus/client_golang/prometheus"

// RepoTarget is the target label of the local repository in paddock_backup_last_success_timestamp_seconds.
const RepoTarget = "repo"

// Metrics are the backup role's metrics (plan M15 decision 19).
type Metrics struct {
	lastSuccess  *prometheus.GaugeVec
	reachable    *prometheus.GaugeVec
	held         *prometheus.GaugeVec
	keyConfirmed prometheus.Gauge
	runs         *prometheus.CounterVec
	repoBytes    *prometheus.GaugeVec
	walArchived  *prometheus.GaugeVec
	// series counts the age series the role exports when it works (kinds × (repository + enabled targets)), so that
	// PaddockBackupAgeMissing notices a series that never appears.
	series     prometheus.Gauge
	walStanzas prometheus.Gauge
	// escrowUnevidenced and escrowSuspicious describe the last successful escrow bucket listing (plan M15,
	// amendment 2026-11-05, A2 note b).
	escrowUnevidenced prometheus.Gauge
	escrowSuspicious  prometheus.Gauge
	// leader is 1 while this process holds the backup leader lock; leaderLost counts the leaderships lost with their
	// connection (decisions-alpha10 §50).
	leader     prometheus.Gauge
	leaderLost prometheus.Counter
}

// NewMetrics registers the metrics with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		lastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "paddock_backup_last_success_timestamp_seconds",
			Help: "Time of the newest backup of each kind in the local repository (target repo) and on each target after its last successful mirror; 0 before the first.",
		}, []string{"kind", "target"}),
		reachable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "paddock_backup_target_reachable",
			Help: "1 when the last mirror to the enabled backup target succeeded, else 0 (unreachable, not mounted, failed).",
		}, []string{"target"}),
		held: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "paddock_backup_target_held_files",
			Help: "Objects the enabled backup target keeps although the local set lacks them, because the local expire would not have removed them yet (plan M15, amendment 2026-11-05); a failed mirror keeps the last value.",
		}, []string{"target"}),
		keyConfirmed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "paddock_backup_key_confirmed",
			Help: "1 while a confirmed backup key exists; 0 means that no backup of any kind runs.",
		}),
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "paddock_backup_runs_total",
			Help: "Backup runs recorded by the backup role by kind and outcome.",
		}, []string{"kind", "outcome"}),
		repoBytes: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "paddock_backup_repo_bytes",
			Help: "Bytes used and free on the file system of the local backup repository.",
		}, []string{"what"}),
		walArchived: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "paddock_backup_wal_last_archived_timestamp_seconds",
			Help: "Modification time of the newest archived WAL segment of each pgBackRest stanza in the local repository; 0 before the first.",
		}, []string{"stanza"}),
		series: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "paddock_backup_age_series",
			Help: "Number of paddock_backup_last_success_timestamp_seconds series the backup role exports (0 without a confirmed key).",
		}),
		walStanzas: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "paddock_backup_wal_stanzas",
			Help: "Number of pgBackRest stanzas whose WAL archive age the backup role exports (0 without a confirmed key).",
		}),
		escrowUnevidenced: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "paddock_backup_escrow_unevidenced_missing",
			Help: "Escrowed LUKS headers of the local set that the last successful escrow bucket listing lacks without Destroy evidence; they are held everywhere.",
		}),
		escrowSuspicious: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "paddock_backup_escrow_listing_suspicious",
			Help: "1 when the last escrow bucket listing lacked, without Destroy evidence, all or more than a tenth of the local set's headers (empty or wrong bucket): nothing is copied or deleted.",
		}),
		leader: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "paddock_backup_leader",
			Help: "1 while this backup role process holds the leader lock and runs rounds and mirror lanes; 0 while it stands by.",
		}),
		leaderLost: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "paddock_backup_leader_lost_total",
			Help: "Leaderships this backup role process lost because the connection holding the leader lock stopped answering.",
		}),
	}
	reg.MustRegister(m.lastSuccess, m.reachable, m.held, m.keyConfirmed, m.runs, m.repoBytes, m.walArchived, m.series,
		m.walStanzas, m.escrowUnevidenced, m.escrowSuspicious, m.leader, m.leaderLost)
	return m
}
