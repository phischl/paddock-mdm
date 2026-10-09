# pgBackRest for the control plane's PostgreSQL databases (plan M6a decision 4, ADR 0016): the Debian package on the
# pinned Debian base. It runs as uid 999, the postgres user of the PostgreSQL image, because it reads the data
# directories of the databases it backs up.
ARG COMPILER_RUNTIME_IMAGE
FROM ${COMPILER_RUNTIME_IMAGE}
# apt-get upgrade: security fixes released after the pinned base digest (trivy image scan).
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends pgbackrest ca-certificates && rm -rf /var/lib/apt/lists/* \
    && if id postgres >/dev/null 2>&1; then groupmod --gid 999 postgres && usermod --uid 999 --gid 999 postgres; \
       else groupadd --system --gid 999 postgres \
         && useradd --system --uid 999 --gid 999 --home-dir /var/lib/postgresql --shell /usr/sbin/nologin postgres; fi \
    && rm -f /etc/pgbackrest.conf && rm -rf /etc/pgbackrest \
    # ssl-cert (a dependency) generates a snakeoil key pair nothing here uses.
    && rm -f /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem \
    && install -d -o 999 -g 999 -m 700 /var/log/pgbackrest /var/lib/pgbackrest /tmp/pgbackrest \
       /var/lib/postgresql/data /pgbackrest-spool/paddock /pgbackrest-spool/authentik \
    && install -d -o 999 -g 999 -m 2775 /var/run/postgresql
COPY --chmod=0755 deploy/compose/pgbackrest/run.sh /usr/local/bin/paddock-pgbackrest
USER 999:999
ENTRYPOINT ["/usr/local/bin/paddock-pgbackrest"]
