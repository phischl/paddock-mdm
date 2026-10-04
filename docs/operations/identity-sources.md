# Identity sources: synced users and groups

Paddock manages the users of an organization in its bundled Authentik (architecture §9.2, plan M3a decisions 2 and
3). There are two kinds of users and groups:

| Kind | Created by | Editable in Paddock |
| --- | --- | --- |
| Local user | Paddock (`POST /api/v1/users`, portal *Users*) | display name, email, lock, groups, assignments |
| Synced user | an upstream source in Authentik (Entra ID, LDAP, SCIM, …) | lock, Paddock groups, assignments only |
| Local group `paddock.<slug>.g.<group>` | Paddock | name and members |
| Imported group `paddock.<slug>.s.<group>` | Paddock, mirroring an upstream group | name only; members follow upstream |

Upstream-owned attributes of synced users (username, display name, email, password) and the members of imported
groups are read-only in Paddock; changing them answers 409 `attribute_owned_upstream`. Change them in the upstream
directory.

## Connecting an upstream source (platform operator)

Paddock does not provision upstream sources; the platform operator configures them in Authentik:

1. Create the source in Authentik (for example an LDAP source or a SCIM provider) as described in the Authentik
   documentation. Bind it to the flows of the organization's users as usual.
2. Add a **property mapping** to the source that makes every user of the organization a **direct member** of the
   organization's root group `paddock.<slug>` (for example `paddock.acme`). Only direct members of the root group are
   users of the organization; members of other groups are not synced.
3. Do **not** set the user attribute `paddock_managed`: it marks the users Paddock created itself, which are not
   synced.
4. Usernames must be unique across all organizations. A synced user whose username already belongs to a user of
   another organization is skipped; the worker records one failed `user.synced_added` event with error code
   `username_taken` and retries it once a day.

## What the worker does

The `paddock-worker` role runs two rounds for every active organization (only one replica acts at a time):

| Round | Default interval | Setting | Work |
| --- | --- | --- | --- |
| Sync | 5 minutes | `PADDOCK_IDENTITY_SYNC_INTERVAL` | Adds new synced users (`user.synced_added`, actor system), removes users that left `paddock.<slug>` together with their group memberships and assignments (`user.synced_removed`), copies changed upstream attributes; copies the members of every imported upstream group that are users of the organization into its mirror group, in Paddock and in Authentik (`user_group.member_added`/`member_removed`, actor system) |
| Reconcile | 10 minutes | `PADDOCK_IDENTITY_RECONCILE_INTERVAL` | Re-creates or corrects the organization's Authentik groups and its device login provider, application, `groups` claim mapping and access policy; keeps the per-device login groups `paddock.<slug>.d.<device_id>` equal to the directly assigned users and deletes them for devices without direct users and for retired devices |

The worker needs `PADDOCK_AUTHENTIK_URL` and `PADDOCK_AUTHENTIK_TOKEN_FILE` (the `paddock-service` token). The
development stack runs the sync round every 60 seconds.

Consequences:

- A new upstream user appears in Paddock within one sync round; a user removed upstream loses its Paddock groups and
  assignments within one sync round.
- Membership changes of imported groups reach Paddock (and the devices' sudo rights) within one sync round. A lock
  does not depend on this delay: it acts on the user directly (architecture §9.5).

## Importing an upstream group

In the portal (*Groups → Import*) or with `POST /api/v1/user-groups` and `upstream_group_id`, an administrator picks an
Authentik group outside Paddock's namespace (`GET /api/v1/upstream-groups`) and gives it a slug. Paddock creates the
mirror group `paddock.<slug>.s.<group_slug>` with the upstream group's current members of the organization. Upstream
names may contain `:` or spaces, which Himmelblau drops from the `groups` claim; the mirror gives every group a
claim-safe name that login assignments and the device allow list use.
