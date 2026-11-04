package backupset

import (
	"encoding/json"
	"fmt"
	"slices"
)

// Kinds are what one backup run backs up (plan M15 decision 1, in the order of the overview).
var Kinds = []string{"postgres", "authentik", "openbao", "fleet", "escrow"}

// ValidKind reports whether k is one of Kinds.
func ValidKind(k string) bool { return slices.Contains(Kinds, k) }

// Settings are the settings of a target without its credentials: the JSON of backup_target.settings, which the api
// writes and the backup role and the host's backup-target apply read. Only the fields of the target's type are set;
// Path is the local directory of a local target and the relative path below the share or export otherwise.
type Settings struct {
	Path     string `json:"path,omitempty"`
	Host     string `json:"host,omitempty"`
	Share    string `json:"share,omitempty"`
	Username string `json:"username,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Export   string `json:"export,omitempty"`
	Options  string `json:"options,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Bucket   string `json:"bucket,omitempty"`
	Region   string `json:"region,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	CAPEM    string `json:"ca_pem,omitempty"`
}

// Credentials are the secrets of a target, Transit-encrypted (backup-wrap) into backup_target.credentials_ciphertext:
// username and password of an SMB target, access_key and secret_key of an S3 target (plan M15 decision 10).
type Credentials struct {
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
}

// SettingsOf returns the settings of t's type; an S3 target without a region gets DefaultRegion.
func SettingsOf(t Target) Settings {
	switch t.Type {
	case TypeLocal:
		return Settings{Path: t.Local.Path}
	case TypeSMB:
		return Settings{Host: t.SMB.Host, Share: t.SMB.Share, Path: t.SMB.Path, Username: t.SMB.Username,
			Domain: t.SMB.Domain, Options: t.SMB.Options}
	case TypeNFS:
		return Settings{Host: t.NFS.Host, Export: t.NFS.Export, Path: t.NFS.Path, Options: t.NFS.Options}
	case TypeS3:
		region := t.S3.Region
		if region == "" {
			region = DefaultRegion
		}
		return Settings{Endpoint: t.S3.Endpoint, Bucket: t.S3.Bucket, Region: region, Prefix: t.S3.Prefix,
			CAPEM: t.S3.CAPEM}
	}
	return Settings{}
}

// CredentialsOf returns the secrets of t's type; ok is false for a type without credentials.
func CredentialsOf(t Target) (c Credentials, ok bool) {
	switch t.Type {
	case TypeSMB:
		return Credentials{Username: t.SMB.Username, Password: t.SMB.Password}, true
	case TypeS3:
		return Credentials{AccessKey: t.S3.AccessKey, SecretKey: t.S3.SecretKey}, true
	}
	return Credentials{}, false
}

// ParseSettings decodes backup_target.settings.
func ParseSettings(raw []byte) (Settings, error) {
	var s Settings
	if err := json.Unmarshal(raw, &s); err != nil {
		return Settings{}, fmt.Errorf("backupset: target settings: %w", err)
	}
	return s, nil
}

// Mounted reports whether a target of type t is a volume the host mounts (local, SMB, NFS): such a target has a host
// state and a host revision, an S3 target has neither (plan M15 decision 10).
func Mounted(t TargetType) bool { return t == TypeLocal || t == TypeSMB || t == TypeNFS }

// DestinationChange returns the first setting of type typ that decides where its credentials go and differs between
// cur and next, as "<type>.<json name>", or "" when none does. Stored credentials stay only for the same destination:
// the api cannot decrypt them, so without this a changed host, share, domain, endpoint or CA would send the stored
// SMB password or S3 key to a server of the caller's choosing. SMB options count because mount.cifs options such as
// ip=, port= and sec= redirect or weaken the login; path and prefix stay on the same server and do not count.
func DestinationChange(typ TargetType, cur, next Settings) string {
	var fields [][3]string
	switch typ {
	case TypeSMB:
		fields = [][3]string{
			{"smb.host", cur.Host, next.Host},
			{"smb.share", cur.Share, next.Share},
			{"smb.domain", cur.Domain, next.Domain},
			{"smb.username", cur.Username, next.Username},
			{"smb.options", cur.Options, next.Options},
		}
	case TypeS3:
		fields = [][3]string{
			{"s3.endpoint", cur.Endpoint, next.Endpoint},
			{"s3.bucket", cur.Bucket, next.Bucket},
			{"s3.region", cur.Region, next.Region},
			{"s3.ca_pem", cur.CAPEM, next.CAPEM},
		}
	}
	for _, f := range fields {
		if f[1] != f[2] {
			return f[0]
		}
	}
	return ""
}
