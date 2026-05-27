## Tools

This is a collection of standalone tools for IT-Security / Pentesting purposes.

### Keeping tools up to date

`update.sh` fetches the latest upstream version of every tool tracked in this
repo. It's best-effort — a single failure is logged and the run continues.

```sh
./update.sh                  # update everything
./update.sh --list           # print the registry without doing anything
./update.sh --only <pat>     # only entries whose name contains <pat> (case-insensitive)
./update.sh --skip <pat>     # skip entries whose name contains <pat>
GITHUB_TOKEN=... ./update.sh # raise GitHub's 60/hr API rate limit
```

Requires `curl`, `git`, `rsync`, `unzip`, `tar`, `gzip`, `find`, and `file`.

Notes:
- Local fork: `Bruteforce/su-bruteforce` points at `Mag1cByt3s/su-bruteforce`.
- A handful of entries are intentionally skipped (frozen CVE PoCs, static
  portable binaries with no canonical upstream, blog-snippet helpers,
  source-only repos). The script prints the reason for each skip.
- `git_export` adds files from upstream without deleting locally-added files,
  so READMEs / bundles you've added by hand survive an update. Run with
  `git stash` first if you want to keep uncommitted local edits to upstream
  files.
