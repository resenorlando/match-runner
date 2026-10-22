# batch runner

Runs private batch jobs on GitHub Actions runners. Everything job-specific is encrypted
(AES-256-GCM, a fresh key per run, destroyed after use) or kept in repository secrets.

## How it stays private

- The repository holds only this harness and `jobs/<id>.enc` ciphertext files.
- Each run's key is a one-off repository secret, deleted together with the run's logs and
  artifacts as soon as the results are collected.
- Tool setup comes from a repository secret and runs with its output hidden. The `w` user that
  runs jobs has no sudo rights, and its setup processes are killed before the job is decrypted.
- `worker.py` decrypts the job inside new network, mount and PID namespaces (loopback only,
  private empty /run, /tmp and /dev/shm), and refuses to read the key unless only loopback exists.
  The job runs as `w` with no new privileges and no capabilities. Results are encrypted,
  plaintext is deleted, and only ciphertext is uploaded (kept for 1 day). The public log shows
  one fixed line per machine.
- The workflow runs only on manual dispatch (never for pull requests), uses only GitHub's own
  actions pinned to commit hashes, installs hash-pinned packages, and has a read-only token.

## Limits

- GitHub's own infrastructure runs the decrypted job.
- Public metadata: when runs happen, how many machines, how long they take, and sizes rounded up
  to 1 MiB.
