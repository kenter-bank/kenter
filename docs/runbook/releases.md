# Releases

How a release is signed, and how to check one before you install it.

## What is signed

A release is a git tag plus a set of packages: the Windows MSI and the Linux
`.deb` files. The packages themselves carry no signature. Instead:

- **`SHA256SUMS`** lists the SHA-256 hash of every package, and
  **`SHA256SUMS.sig`** is a signature over that file.
- **The release tag** (for example `v0.2.4`) is a signed git tag, so the
  source a release was built from can be checked too.

Both are signed with the same key, an SSH signing key held on a hardware
token. Its public half is in [`allowed_signers`](https://github.com/kenter-bank/kenter/blob/main/allowed_signers)
at the repository root:

| | |
|---|---|
| Signer | `358557624+kenter-bank@users.noreply.github.com` |
| Key type | `sk-ssh-ed25519@openssh.com` |
| Fingerprint | `SHA256:9NAwKM6LRNOM/se1A1AXliFoItw1EPX4dw9pdzmeogw` |

Checking a signature needs OpenSSH 8.2 or newer (`ssh -V`). It ships with
current Linux, macOS and Windows 10/11.

## Verifying a download

Put the packages, `SHA256SUMS`, `SHA256SUMS.sig` and `allowed_signers` in one
folder, then:

```bash
ssh-keygen -Y verify -f allowed_signers \
  -I 358557624+kenter-bank@users.noreply.github.com \
  -n file -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

The first command must print `Good "file" signature for
358557624+kenter-bank@users.noreply.github.com`. The second must print `OK`
for each package you downloaded. Anything else means the files are not the
ones that were signed: do not install them.

On Windows, without `sha256sum`, compare the hash by hand:

```powershell
(Get-FileHash .\kenter-0.2.4-mainnet-x64.msi).Hash.ToLower()
```

and check it against the line for that file in `SHA256SUMS`.

::: tip Get `allowed_signers` from the repository, not from the download
A signature only proves something if the key comes from somewhere the
attacker does not control. Take `allowed_signers` from a clone of the
repository, and check its fingerprint against the one above.
:::

## Verifying the source

```bash
git clone https://github.com/kenter-bank/kenter.git
cd kenter
git config gpg.ssh.allowedSignersFile allowed_signers
git verify-tag v0.2.4
```

`git verify-tag` must print a `Good "git" signature`. GitHub also marks tags
signed with this key as **Verified**.

To check a deployed contract against a tag, build it from that tag on x86_64
Linux and compare hashes; see [Build and run](/runbook/build-and-run#contracts).

## Making a release

On the release machine (x86_64 Linux, with the hardware token):

1. Build the packages: the `.deb` files on the release machine, the MSI on
   Windows. Each packaging script adds its file's line to `dist/SHA256SUMS`.
   Copy the MSI into the release machine's `dist/` and add its line there
   too (`cd dist && sha256sum kenter-*.msi >> SHA256SUMS`), so one file lists
   every package.
2. Sign the checksums:
   ```bash
   scripts/sign-release.sh
   ```
   It checks every listed file against its hash, signs, and verifies the
   signature against `allowed_signers`. The token asks for its PIN and a
   touch.
3. Tag the commit the packages were built from and push the tag:
   ```bash
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_kenter_sign.pub
   git tag -s v0.2.4 -m "Kenter 0.2.4"
   git push origin v0.2.4
   ```
4. Publish the packages, `SHA256SUMS` and `SHA256SUMS.sig` together.

If the signing key ever changes, `allowed_signers` changes in a commit of its
own, and the old key stays listed with a `valid-before` date so earlier
releases still verify.
