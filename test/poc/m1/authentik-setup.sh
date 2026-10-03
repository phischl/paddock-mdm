#!/usr/bin/env bash
# Idempotent Authentik setup for the M1 PoC (plan decision 4), only through the Authentik API with the bootstrap
# token. Creates the OIDC provider/application paddock-device-acme (public client, device code + refresh token),
# the access policy, the device code flow of the default brand, group paddock:acme:locked and the test users
# dave/erin (paddock:acme) and frank (paddock:globex) with TOTP enrolled through the real setup flow.
#
# Usage: authentik-setup.sh setup | status | lock <user> | unlock <user> | approve <user> <user_code>
#   <user> is the short name (dave, erin, frank) or the full username.
set -euo pipefail

source "$(dirname "$0")/lib.sh"

ORG=acme
APP=paddock-device-$ORG
DEVICE_FLOW=paddock-device-code
LOCK_GROUP="paddock:$ORG:locked"
TOKEN_FILE="$STACK_SECRETS/authentik_bootstrap_token"
export AUTH_URL CADDY_ROOT POC_SECRETS

declare -A USER_GROUP=([dave@acme.test]="paddock:acme" [erin@acme.test]="paddock:acme" [frank@globex.test]="paddock:globex")

full_user() {
    case "$1" in
        *@*) echo "$1" ;;
        dave | erin) echo "$1@acme.test" ;;
        frank) echo "$1@globex.test" ;;
        *) die "unknown user $1" ;;
    esac
}

# api <method> <path> [json-body] calls the Authentik API and prints the response body; fails on HTTP >= 300.
api() {
    local method=$1 path=$2 body=${3:-} resp code
    local -a args=(-X "$method" -H "Authorization: Bearer $(cat "$TOKEN_FILE")" -H "Accept: application/json")
    [[ -n "$body" ]] && args+=(-H "Content-Type: application/json" --data "$body")
    resp=$(curl_auth -w '\n%{http_code}' "${args[@]}" "$AUTH_URL/api/v3$path")
    code=${resp##*$'\n'}
    resp=${resp%$'\n'*}
    if ((code >= 300)); then
        log "Authentik $method $path: HTTP $code: $resp"
        return 1
    fi
    printf '%s' "$resp"
}

# first <path> <jq-filter> prints the first matching value of a list endpoint (empty if none).
first() { api GET "$1" | jq -r "[.results[] | $2] | first // empty"; }

group_pk() { first "/core/groups/?include_users=false&name=$(jq -rn --arg v "$1" '$v|@uri')" '.pk'; }
user_pk() { first "/core/users/?username=$(jq -rn --arg v "$1" '$v|@uri')" '.pk'; }
flow_pk() { first "/flows/instances/?slug=$1" '.pk'; }
scope_pk() { first "/propertymappings/provider/scope/?managed=$1" '.pk'; }

# totp_devices <user-pk> prints the TOTP devices of a user as JSON array (the admin list has no user filter).
totp_devices() { api GET "/authenticators/admin/totp/?page_size=500" | jq --argjson u "$1" '[.results[] | select(.user.pk == $u)]'; }

ensure_group() {
    local pk
    pk=$(group_pk "$1")
    [[ -n "$pk" ]] || pk=$(api POST /core/groups/ "$(jq -n --arg n "$1" '{name: $n}')" | jq -r .pk)
    echo "$pk"
}

ensure_secret() {
    local f="$POC_SECRETS/$1"
    if [[ ! -s "$f" ]]; then
        # Not random_secret from lib.sh: its tr|head pipe dies of SIGPIPE under pipefail.
        (umask 077; head -c 48 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | cut -c1-24 >"$f")
    fi
}

setup_flow() {
    local pk brand
    pk=$(flow_pk "$DEVICE_FLOW")
    if [[ -z "$pk" ]]; then
        pk=$(api POST /flows/instances/ "$(jq -n --arg s "$DEVICE_FLOW" '{
            slug: $s, name: "Paddock device code", title: "Paddock device sign-in",
            designation: "stage_configuration", authentication: "require_authenticated"}')" | jq -r .pk)
        log "created flow $DEVICE_FLOW"
    fi
    brand=$(first "/core/brands/?default=true" '.brand_uuid')
    api PATCH "/core/brands/$brand/" "$(jq -n --arg f "$pk" '{flow_device_code: $f}')" >/dev/null
}

setup_provider() {
    local pk app policy mappings auth_flow authz_flow inval_flow signing body
    auth_flow=$(flow_pk default-authentication-flow)
    authz_flow=$(flow_pk default-provider-authorization-implicit-consent)
    inval_flow=$(flow_pk default-provider-invalidation-flow)
    signing=$(first "/crypto/certificatekeypairs/?name=$(jq -rn '"authentik Self-signed Certificate"|@uri')" '.pk')
    mappings=$(jq -n --arg a "$(scope_pk goauthentik.io/providers/oauth2/scope-openid)" \
        --arg b "$(scope_pk goauthentik.io/providers/oauth2/scope-email)" \
        --arg c "$(scope_pk goauthentik.io/providers/oauth2/scope-profile)" \
        --arg d "$(scope_pk goauthentik.io/providers/oauth2/scope-offline_access)" \
        --arg e "$(scope_pk io.paddock/scope-groups)" '[$a, $b, $c, $d, $e]')
    body=$(jq -n --arg n "$APP" --arg af "$auth_flow" --arg zf "$authz_flow" --arg if "$inval_flow" \
        --arg sk "$signing" --argjson pm "$mappings" '{
        name: $n, client_type: "public", client_id: $n,
        grant_types: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token", "authorization_code"],
        authentication_flow: $af, authorization_flow: $zf, invalidation_flow: $if,
        redirect_uris: [{matching_mode: "strict", url: "http://127.0.0.1:8765/callback", redirect_uri_type: "authorization"}],
        signing_key: $sk, include_claims_in_id_token: true, sub_mode: "hashed_user_id", issuer_mode: "per_provider",
        access_token_validity: "minutes=10", refresh_token_validity: "days=30", property_mappings: $pm}')
    pk=$(first "/providers/oauth2/?name=$APP" '.pk')
    if [[ -z "$pk" ]]; then
        pk=$(api POST /providers/oauth2/ "$body" | jq -r .pk)
        log "created provider $APP"
    else
        api PUT "/providers/oauth2/$pk/" "$body" >/dev/null
    fi

    app=$(first "/core/applications/?superuser_full_list=true&slug=$APP" '.pk')
    body=$(jq -n --arg n "$APP" --argjson p "$pk" '{name: $n, slug: $n, provider: $p, policy_engine_mode: "all"}')
    if [[ -z "$app" ]]; then
        app=$(api POST /core/applications/ "$body" | jq -r .pk)
        log "created application $APP"
    else
        api PATCH "/core/applications/$APP/" "$body" >/dev/null
    fi

    # Architecture §2: member of paddock:<slug> (directly or via a sub-group) and not of paddock:<slug>:locked.
    body=$(jq -n --arg n "$APP-access" --arg org "paddock:$ORG" --arg lock "$LOCK_GROUP" '{name: $n, expression:
        ("groups = {g.name for g in request.user.all_groups()}\nreturn \"" + $org + "\" in groups and \"" + $lock + "\" not in groups\n")}')
    policy=$(first "/policies/expression/?name=$APP-access" '.pk')
    if [[ -z "$policy" ]]; then
        policy=$(api POST /policies/expression/ "$body" | jq -r .pk)
    else
        api PATCH "/policies/expression/$policy/" "$body" >/dev/null
    fi
    if [[ -z "$(first "/policies/bindings/?target=$app&policy=$policy" '.pk')" ]]; then
        api POST /policies/bindings/ "$(jq -n --arg t "$app" --arg p "$policy" '{target: $t, policy: $p, order: 0, enabled: true, timeout: 30}')" >/dev/null
        log "bound policy $APP-access"
    fi
}

setup_user() {
    local user=$1 group=$2 pk gpk devices
    ensure_secret "password_$user"
    pk=$(user_pk "$user")
    if [[ -z "$pk" ]]; then
        pk=$(api POST /core/users/ "$(jq -n --arg u "$user" '{username: $u, name: $u, email: $u, type: "internal", is_active: true, path: "paddock-poc"}')" | jq -r .pk)
        log "created user $user"
    fi
    api POST "/core/users/$pk/set_password/" "$(jq -n --arg p "$(poc_secret "password_$user")" '{password: $p}')" >/dev/null
    gpk=$(group_pk "$group")
    [[ -n "$gpk" ]] || die "group $group missing (run make dev-seed first)"
    api POST "/core/groups/$gpk/add_user/" "$(jq -n --argjson u "$pk" '{pk: $u}')" >/dev/null

    devices=$(totp_devices "$pk" | jq -r '.[].pk')
    if [[ -n "$devices" && ! -s "$POC_SECRETS/totp_$user" ]]; then
        # The secret of an existing device is unknown: replace the device.
        for d in $devices; do api DELETE "/authenticators/admin/totp/$d/" >/dev/null; done
        devices=
    fi
    if [[ -z "$devices" ]]; then
        rm -f "$POC_SECRETS/totp_$user" "$POC_SECRETS/totp_$user.last"
        local secret
        secret=$("$POC_DIR/akflow.py" enroll-totp "$user")
        (umask 077; printf '%s' "$secret" >"$POC_SECRETS/totp_$user")
        log "enrolled TOTP for $user"
    fi
}

revoke_user_tokens() {
    local pk=$1 id
    for id in $(api GET "/oauth2/refresh_tokens/?user=$pk&page_size=500" | jq -r '.results[].id'); do
        api DELETE "/oauth2/refresh_tokens/$id/" >/dev/null
    done
    for id in $(api GET "/oauth2/access_tokens/?user=$pk&page_size=500" | jq -r '.results[].id'); do
        api DELETE "/oauth2/access_tokens/$id/" >/dev/null
    done
    for id in $(api GET "/core/authenticated_sessions/?user__username=$(jq -rn --arg v "$2" '$v|@uri')&page_size=500" | jq -r '.results[].uuid'); do
        api DELETE "/core/authenticated_sessions/$id/" >/dev/null
    done
}

cmd_setup() {
    mkdir -p "$POC_SECRETS"
    chmod 700 "$POC_SECRETS"
    ensure_group "$LOCK_GROUP" >/dev/null
    setup_flow
    setup_provider
    local u
    for u in "${!USER_GROUP[@]}"; do setup_user "$u" "${USER_GROUP[$u]}"; done
    cmd_status
}

cmd_status() {
    local pk app
    echo "== provider"
    api GET "/providers/oauth2/?name=$APP" | jq '.results[] | {name, client_id, client_type, grant_types,
        refresh_token_validity, access_token_validity, issuer_mode, sub_mode, scopes: [.property_mappings | length],
        redirect_uris: [.redirect_uris[].url]}'
    echo "== application + policy bindings"
    app=$(first "/core/applications/?superuser_full_list=true&slug=$APP" '.pk')
    api GET "/core/applications/$APP/" | jq '{slug, provider_obj: .provider_obj.name, policy_engine_mode}'
    api GET "/policies/bindings/?target=$app" | jq '.results[] | {order, policy: .policy_obj.name, expression: .policy_obj.expression}'
    echo "== brand device code flow"
    api GET "/core/brands/?default=true" | jq '.results[] | {domain, flow_device_code}'
    echo "== users"
    for u in "${!USER_GROUP[@]}"; do
        pk=$(user_pk "$u")
        api GET "/core/users/$pk/" | jq -c --argjson totp "$(totp_devices "$pk" | jq '[.[] | {pk, name}]')" \
            '{username, is_active, groups: [.groups_obj[].name], totp: $totp}'
    done
    echo "== discovery as seen by the VMs ($AUTH_URL)"
    curl_auth "$AUTH_URL/application/o/$APP/.well-known/openid-configuration" | jq '{issuer, device_authorization_endpoint,
        grant_types_supported, scopes_supported}'
}

cmd_lock() {
    local user pk gpk
    user=$(full_user "$1")
    pk=$(user_pk "$user")
    gpk=$(group_pk "$LOCK_GROUP")
    echo "lock_api_call_start=$(ts)"
    api POST "/core/groups/$gpk/add_user/" "$(jq -n --argjson u "$pk" '{pk: $u}')" >/dev/null
    revoke_user_tokens "$pk" "$user"
    echo "lock_api_call_done=$(ts)"
}

cmd_unlock() {
    local user pk gpk
    user=$(full_user "$1")
    pk=$(user_pk "$user")
    gpk=$(group_pk "$LOCK_GROUP")
    api POST "/core/groups/$gpk/remove_user/" "$(jq -n --argjson u "$pk" '{pk: $u}')" >/dev/null
    echo "unlocked=$(ts)"
}

case "${1:-}" in
    setup) cmd_setup ;;
    status) cmd_status ;;
    lock) cmd_lock "${2:?user}" ;;
    unlock) cmd_unlock "${2:?user}" ;;
    approve) "$POC_DIR/akflow.py" device "$(full_user "${2:?user}")" "${3:?user_code}" ;;
    *) die "usage: $0 setup|status|lock <user>|unlock <user>|approve <user> <user_code>" ;;
esac
