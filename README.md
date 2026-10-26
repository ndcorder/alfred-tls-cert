# TLS Cert for Alfred

Check a server's TLS certificate from Alfred: expiry, SANs, issuer, trust and hostname verification, protocol, cipher, chain and SHA-256 fingerprint.

The result is three rows (summary, SANs, verify result and chain). Each row has an icon for its state, so an expired or untrusted certificate stands out before you read the title.

## Usage

Type `cert` and a host, `host:port` or URL, for example `cert github.com`, `cert mail.example.com:993` or `cert https://example.com/login`. The scheme, user info and path are stripped and the port defaults to 443. IPv6 addresses go in brackets: `cert [2001:db8::1]:8443`.

| Key | Action |
|---|---|
| ↩ | Copy a plain-text summary of everything |
| ⌘ ↩ | Open crt.sh for the host |
| ⌘ C | Copy the row's value (summary, SAN list or SHA-256 fingerprint) |
| ⌘ L | Show the full summary in Large Type |

| Icon | Meaning |
|---|---|
| Green lock | In date, trusted, and the certificate covers the host name |
| Amber clock | Expires within the warning period |
| Red seal | Expired, or not valid yet |
| Red shield | Untrusted chain, self-signed, or host name mismatch |
| Blue list | The SANs row |
| Green or red link | The verify result and chain row |
| Grey globe | DNS lookup failed, connection refused, or network unreachable |
| Amber hourglass | No answer within 8 seconds |

An expired certificate gets the seal even though verification also fails, because expiry is the more specific reason. A trust or name problem outranks a certificate that only expires soon.

## Configuration

Open the workflow in Alfred Preferences and click Configure Workflow.

| Setting | Default | Meaning |
|---|---|---|
| Warning days | `30` | Warn when the certificate expires in fewer than this many days |

Successful checks are cached for five minutes in Alfred's workflow cache. Errors are never cached, so retyping the host retries at once.

## Requirements

- macOS with Alfred 5 and the Powerpack
- `/usr/bin/python3` (installed with the Xcode Command Line Tools)
- OpenSSL from Homebrew at `/opt/homebrew/bin/openssl` is used when present. Otherwise the workflow uses `/usr/bin/openssl` (LibreSSL), which cannot verify host names, so the workflow matches the name against the SANs itself.

## Icons

Icons are drawn by `iconkit.js`, a small JavaScript for Automation script that uses AppKit, so there is nothing to install. The set is pre-rendered into `icons/`. After changing the icon table in `cert.py`, run `/usr/bin/python3 -B make_icons.py` to render it again. If an icon file is missing, Alfred shows the workflow icon instead.

## Install

Download the latest `.alfredworkflow` from Releases and open it.

To work on it, clone the repository and symlink it into Alfred's workflows folder:

```sh
git clone https://github.com/ndcorder/alfred-tls-cert.git
ln -s "$PWD/alfred-tls-cert" "<Alfred preferences>/Alfred.alfredpreferences/workflows/alfred-tls-cert"
```

Your Configure Workflow values are saved in `prefs.plist` in the workflow folder, which is ignored by git.

## Development

```sh
/usr/bin/python3 -B -m unittest test_cert
```

Tests mock openssl and osascript and make no network calls.

## Licence

MIT. See [LICENSE](LICENSE).
