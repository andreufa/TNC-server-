# Push to GitLab

## Prerequisites
- Git installed
- GitLab account
- Repository created on GitLab (e.g. `https://gitlab.com/yourname/tnc-server`)

## Steps

```sh
# 1. Add remote
git remote add gitlab https://gitlab.com/yourname/tnc-server.git

# 2. Push
git push -u gitlab crypto-handshake
```

## Multiple remotes

```sh
# List remotes
git remote -v

# Push to both
git push origin crypto-handshake
git push gitlab crypto-handshake
```

## CI/CD (optional)
Add `.gitlab-ci.yml` to build the Docker image:

```yaml
build:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build -t tnc-server .
```
