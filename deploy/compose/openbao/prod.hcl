# OpenBao production configuration (plan M6a decision 1, compose.prod.yaml): TLS on the listener with the certificate
# of the control plane's internal CA (`make prod-secrets`), whose SANs cover openbao, 127.0.0.1 and the interconnect
# address the audit writer uses. Integrated Raft storage on the openbao-data volume.
ui            = false
api_addr      = "https://openbao:8200"
cluster_addr  = "https://openbao:8201"
log_level     = "info"

storage "raft" {
  path    = "/openbao/file"
  node_id = "openbao-1"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/run/secrets/openbao_tls_crt"
  tls_key_file    = "/run/secrets/openbao_tls_key"
  tls_min_version = "tls12"
}
