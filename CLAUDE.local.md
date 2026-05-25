# CLAUDE.local.md — local-only, gitignored

## Git Push

Use SSH key `mike_id_rsa` for pushes to mikedamoiseau repos:
```bash
GIT_SSH_COMMAND="ssh -i ~/.ssh/mike_id_rsa -o IdentitiesOnly=yes" git push origin <branch-or-tag>
```
