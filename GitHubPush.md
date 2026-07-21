# Push to GitHub

## Prerequisites
- Git installed
- GitHub account
- Repository created on GitHub (e.g. `https://github.com/yourname/tnc-server`)

## Steps

```sh
# 1. Add remote (if not already set)
git remote add origin https://github.com/yourname/tnc-server.git

# 2. Push the current branch
git push -u origin crypto-handshake

# 3. For subsequent pushes
git push
```

## Pushing a new branch

```sh
git checkout -b feature/my-feature
git push -u origin feature/my-feature
```

## Notes
- The `.gitignore` excludes: `*.exe`, `.env`, `*.pem` (private keys), `tnc-pgdata/`
- Public keys (`.pem` with `_public` suffix) and stub keys are tracked intentionally
