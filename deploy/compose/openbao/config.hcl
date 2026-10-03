# OpenBao server configuration (plan M0 §6.8). Integrated Raft storage on the openbao-data volume.
ui            = false
api_addr      = "http://openbao:8200"
cluster_addr  = "http://openbao:8201"
log_level     = "info"

storage "raft" {
  path    = "/openbao/file"
  node_id = "openbao-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  # TLS terminates inside the trusted Compose network in v1; see docs/operations/openbao.md for production TLS.
  tls_disable     = true
}
