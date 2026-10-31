# Getting started: from the first administrator to the first configured device

This is the one path to follow after `./paddock up` (`docs/operations/install.md` section 8) reports a healthy
control plane. It ends with an enrolled device that receives its first configuration. Each step names where it runs
and why it exists; the details live in the linked runbooks.

Where a step runs:

| Where | Meaning |
| --- | --- |
| **Authentik** | `https://auth.<domain>/if/admin/`, the bundled identity provider |
| **Portal** | `https://admin.<domain>`, signed in as the role the step names |
| **Host** | a shell in the bundle directory of the control plane |
| **Device** | the laptop that is to be managed, as root |

Two roles are involved: the **platform administrator** (organizations, agent releases, IP allow list) and the
**organization administrator** (users, enrollment tokens, devices, configuration of one organization). One identity
may hold both and switch between them in the portal's user menu (`docs/operations/install.md` section 9, step 3).

## 1. First platform administrator (Authentik)

*Why: the portal has no account until someone exists in the group `paddock.platform.admins`, and privileged actions
need a WebAuthn second factor.*

Sign in to Authentik as `akadmin` with the password in `.secrets/authentik_bootstrap_password`, create the user, enroll
a WebAuthn authenticator for it and add it to `paddock.platform.admins`. Then deactivate `akadmin` or give it a new
password held by the custodians. Details: `docs/operations/install.md` section 9, step 1.

## 2. First organization (Portal, platform administrator)

*Why: every device, user and setting belongs to an organization; the domains decide whether its devices get login
management and a managed local administrator.*

Sign in to the portal (every sign-in asks for the second factor) and create the organization under *Platform* →
*Organizations* **with the domains of its users**. Without a domain its devices get neither login management nor a
managed local administrator. Details: `docs/operations/install.md` section 9, step 2.

## 3. Identity source and first organization administrator (Authentik)

*Why: users and administrators of an organization come from its identity source; the organization administrator is the
role that carries out steps 5 to 8.*

Connect the organization's upstream source (Entra ID, LDAP, SCIM, ...) in Authentik and map its users to be direct
members of `paddock.<slug>`: `docs/operations/identity-sources.md`, "Connecting an upstream source". Make the first
organization administrator a member of `paddock.<slug>.admins`. That person signs in to the portal as organization
administrator; an identity that is also a platform administrator switches roles from the user menu.

## 4. First agent release (Host or Portal, platform administrator)

*Why: devices install and update the agent from a signed release; without a published release there is nothing to
enroll with and the autoinstall refuses to generate (409 `invalid_state`).*

Preferred, when the control plane reaches GitHub: in the portal open *Agent releases*, check for a new release and
import it (needs a step-up). Otherwise, on the **Host**:

```sh
./paddock agent-release <version> <dir>
```

where `<dir>` holds the signed files in the layout of `docs/operations/install.md` section 10. The autoinstall and
route 8b install the newest published release; the staged rollout governs updates, so start it for the
releases that enrolled devices are to receive. In the portal use *Start rollout* on the release
page, or on the **Host**:

```sh
./paddock agent-rollout <version> --waves 100
```

`--waves 100` suits a small fleet or a lab (the default waves may contain none of its devices). Details:
`docs/operations/install.md` section 10 and `docs/operations/agent-releases.md` ("Import from GitHub", "Rolling out",
"From the control-plane host").

## 5. IP allow list (Portal, platform administrator; optional, recommended)

*Why: it limits the portal and the admin API to your office and VPN ranges.*

Open *Platform* → *IP allow list*, add your own address with *Use my address* first, then the other ranges. Do this
after the first sign-ins work, and keep the lockout runbook at hand: `docs/operations/ip-allowlist.md`.

## 6. Break-glass accounts (Portal, organization administrator)

*Why: Paddock alone grants sudo. At the first apply it removes every member of `sudo`, `admin` and `wheel` that is not a
break-glass account or the managed local administrator, so the administrators already on your devices must be listed
before a device enrolls.*

Open *Login & privileges* and enter the existing local administrator accounts of the devices (for example the
installing user). Details: `docs/operations/device-login.md`, "Break-glass accounts and sudo", and
`docs/operations/local-admin.md` for the managed local administrator Paddock creates itself.

## 7. Enrollment token (Portal, organization administrator)

*Why: a device proves it may join the organization with a token; the token also decides the device group and whether
a new device is approved automatically.*

Open *Enrollment tokens* and create one: validity, maximum number of devices, the device group to add enrolled devices
to, and *Approve enrolled devices automatically* if no administrator should approve each device. The portal shows the
enrollment configuration **once**; keep it for step 8. Without automatic approval the device waits as pending until an
administrator approves it on the device's page (*Approve*).

## 8. First device

*Why: this is the point where the control plane meets real hardware. Choose one of the two routes.*

### 8a. New installation with the autoinstall (admin API, then Device)

The portal has no page for the autoinstall. Generate the user-data for the device with `POST /api/v1/autoinstall`,
sent with your portal session from a workstation and the enrollment configuration of step 7 (the curl example is in
`docs/operations/autoinstall.md`, "Generate the user-data"), and install from it. It sets up full-disk
encryption with TPM2 and a boot PIN, installs the agent and enrolls the device itself. The device needs UEFI with
Secure Boot, a TPM 2.0 and a connection to `https://bundles.<domain>/packages/` during the installation. The
user-data is a secret (temporary disk passphrase and enrollment token). Steps, first boot and the boot PIN:
`docs/operations/autoinstall.md` and `docs/operations/disk-recovery.md`.

### 8b. Device that is already installed (Device)

*Why: not every device can be reinstalled. The agent can enroll a running Ubuntu device; its disk encryption is a
separate decision afterwards.*

1. Put the enrollment configuration of step 7 on the device as a file, for example `/root/enroll.json` (mode 0600).
2. Install the two packages of the published release. The edge serves them publicly at
   `https://bundles.<domain>/packages/<version>/<name>_<version>_<arch>.deb` (`docs/operations/agent-releases.md`,
   "Public packages"):

   ```sh
   curl -fsSLO https://bundles.<domain>/packages/<version>/paddock-supervisor_<version>_amd64.deb
   curl -fsSLO https://bundles.<domain>/packages/<version>/paddock-agent_<version>_amd64.deb
   sudo apt install ./paddock-supervisor_<version>_amd64.deb ./paddock-agent_<version>_amd64.deb
   ```

   The agent package depends on the supervisor package; its post-install script installs `paddockd` and starts
   `paddock-supervisor`.
3. Enroll once, as root:

   ```sh
   sudo paddockd enroll --config /root/enroll.json --remove-config
   ```

   Exit code 0 means active, 2 pending approval, 3 rejected, 1 an error. `--remove-config` deletes the file once
   the device is enrolled or pending; add `--proxy <url>` behind an HTTP proxy.
4. If the token does not approve automatically, the command keeps waiting for the approval (for up to 24 hours): approve
   the device in the portal under *Devices* (*Approve*) while it waits. Alternatively run it with `--no-wait`, which
   returns with exit code 2 at once; approve the device, then run the same command again, which resumes the
   enrollment.

An unencrypted device then shows *Not encrypted* in the portal. Whether it can be encrypted in place or has to be
reinstalled with the autoinstall: `docs/operations/autoinstall.md`, "Encrypting an installed device", and
`docs/operations/in-place-encryption.md`.

## 9. First configuration (Portal, organization administrator)

*Why: an enrolled device only checks in until the organization defines something for it.*

Create a first managed file under *Managed files* (for example `/etc/motd` for every device, or for one device group).
Alternatively export the organization with `paddockctl get config > paddock.yml`, edit the file and apply it with
`paddockctl apply -f paddock.yml` (`--dry-run` shows the plan first; `docs/operations/paddockctl.md`,
`docs/operations/api-tokens.md` for the token). The device receives the signed bundle at its next check-in and applies
it; the device page shows the result.

## 10. First user login on the device

*Why: directory users sign in through Himmelblau, not with a local password.*

Optionally restrict who may sign in on the device page (*Login*: users and groups); without an assignment every
user of the organization may sign in. Then on the device choose *Not listed?* at the
login screen and type `name@domain`. The screen shows a code; sign in with it on a second device and set a Hello PIN.
Details and troubleshooting: `docs/operations/device-login.md`, "Signing in (users)".

## Checklist

- [ ] Platform administrator with WebAuthn, `akadmin` deactivated
- [ ] Organization with its domains, identity source connected, organization administrator in `paddock.<slug>.admins`
- [ ] Agent release published and its rollout started
- [ ] IP allow list set (optional)
- [ ] Break-glass accounts set before the first device enrolls
- [ ] Enrollment token created
- [ ] First device active
- [ ] First managed file applied
