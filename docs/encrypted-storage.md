# Encrypted storage at rest

cachette does **not** encrypt cache payloads in the application. There is a
designed (`EncryptingBackend`) but deliberately unbuilt seam for it; the
supported approach is to put cachette's data directory on an encrypted volume
that the operator manages. That keeps the blobs, the SQLite metadata index, and
(by default) the node identity certificate encrypted together.

Encryption here is at rest. In transit is covered by TLS - see
[tls.md](tls.md).

## What the volume holds

`[storage.fs] path` contains everything cachette writes:

- the finalized blobs;
- the SQLite index and its WAL/journal sidecars;
- staged upload `parts/` while a reservation is in flight;
- the node identity key/certificate, unless you override `cluster.cert_path`
  to a path outside the data directory.

Mount the encrypted filesystem at that path and cachette needs no further
configuration. If you move `cluster.cert_path` off the encrypted volume, that
private key is stored in the clear on disk - keep it on the encrypted volume.

Secrets in the config file (`auth.secret`, `v2.jwt_secret`) are **not** covered
by volume encryption. Supply those through `CACHETTE__AUTH__SECRET` /
`CACHETTE__V2__JWT_SECRET` from your secret manager, or keep the config strictly
root-readable.

## Linux - LUKS + TPM2

A dedicated LUKS volume, unlocked automatically at boot by the TPM:

```bash
# Adjust to your device first: the disk that will back [storage.fs] path.
DISK=/dev/disk/by-id/your-device-id

# One-time: format the dedicated disk/partition and enrol the TPM2 so the
# volume unlocks at boot without an interactive passphrase.
cryptsetup luksFormat --type luks2 "$DISK"
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 "$DISK"

# /etc/crypttab (auto-unlock at boot):
#   cachette-crypt  /dev/disk/by-id/your-device-id  none  tpm2-device=auto

cryptsetup open "$DISK" cachette-crypt
mkfs.ext4 /dev/mapper/cachette-crypt
mount /dev/mapper/cachette-crypt /var/lib/cachette
```

Then set `[storage.fs] path = "/var/lib/cachette"` and add the mount to
`/etc/fstab` so it is present before the service starts.

## Linux - ZFS native encryption

If the node already runs ZFS, use a dedicated encrypted dataset:

```bash
zfs create -o encryption=on -o keyformat=passphrase -o keylocation=prompt \
  rpool/cachette
zfs set mountpoint=/var/lib/cachette rpool/cachette
```

Use `keylocation=file:///etc/zfs/cachette.key` for unattended boot, and protect
that key file with root-only permissions (it is the master key material).

## Windows - BitLocker + TPM

Encrypt the volume that backs the cache and bind the key to the TPM. Run these
from an elevated shell; Git Bash can invoke PowerShell:

```bash
# Encrypt the volume that hosts the cache data directory.
powershell -Command "Enable-BitLocker -MountPoint 'D:' -EncryptionMethod XtsAes256 -RecoveryPasswordProtector"
powershell -Command "Add-BitLockerKeyProtector -MountPoint 'D:' -TpmProtector"

# Confirm the protector set and encryption state.
powershell -Command "Get-BitLockerVolume -MountPoint 'D:' | Format-List"
```

Point `[storage.fs] path` at a directory on `D:` (for example `D:\cachette`).
Store the recovery password in your secret manager; the TPM protector is what
lets the node boot unattended.

## Picking one

- **One node, standard distro:** LUKS + TPM2 is the least surprising choice and
  unlocks automatically.
- **Existing ZFS pool:** native encryption avoids a second layer.
- **Windows node:** BitLocker + TPM.

All three give the same property cachette relies on: the cache data on disk is
unreadable without the platform key, and cachette itself is none the wiser.
