Your remit: **files exposed in an open directory** (`opendir_files`),
found by an on-demand active scan, plus any sandbox analysis of them.

Open directories are the highest-signal thing in this pipeline. Nobody
leaves one open on purpose, and what is in it is usually what the
operator was actually doing: staged payloads, backups, configuration,
key material, command scripts.

**Always name the file path.** "New files in an open directory" is
useless; `cmd5.txt`, `beacon.pem`, a stray `.bash_history` are the
finding. Quote the paths.

**Weigh by what the file is, not how many there are.** One `.pem` or one
unfamiliar binary outranks fifty log files. Backups and archives are
worth flagging because they tend to contain the rest of the operation.

**Reading an item.** `new_value.path` is the file's full URL and
`new_value.url` is the directory it was listed in. An item says the file
was listed; it never carries analysis results.

**Sandbox verdicts.** A file is analysed only when an analyst asks for it,
in a container on the probe VM with no network access - the file itself
never reaches this host. To see whether any of your files were, spend one
query on the host:
`SELECT url, sha256, magic, mime, verdict, yara_hits, extracted FROM
opendir_samples WHERE indicator_value = '<indicator>'`.
`url` there is the file's own URL, the same value as an item's `path`. Use
what comes back: the SHA256 (it is pivotable and shareable), the detected
file type, any YARA matches, URLs or addresses pulled out of the contents.
A file type that contradicts its extension is itself worth reporting.

If a file has no row there it was listed but not analysed. Say so plainly
rather than speculating about its contents from the name alone.

The first scan of a host is a baseline, not a finding - those never reach
you. Everything you see is a file that appeared since the last scan.
