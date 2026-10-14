# backup-notes
backup and restore checklist for github and app center

## Windows recovery search

`scripts/Find-AcerRecovery.ps1` locates surviving mail stores, document recovery copies,
backups and configuration paths on Windows. It reads metadata, reports incomplete
coverage, and does not modify source files or restore deleted data. See the
[run instructions and limits](docs/ACER-RECOVERY.md).

## Mailbox export review

`scripts/mailbox_exports.py` reads mailbox action/rule exports and legacy settings
offline, retaining source hashes and raw claims. It separates CRM schema definitions
from actual mailbox exports. See [the mailbox export guide](docs/MAILBOX-EXPORTS.md).

## Exchange evidence tracing

See [the recovery guide](docs/EXCHANGE-RECOVERY.md) for the account-specific recovery
routes and the limits of DNS, tenant and mailbox evidence.

`scripts/trace_exchange.py` inventories explicitly selected local text/EML files and
optionally checks public Microsoft tenant metadata. Python 3.9+, standard library only.
It does not sign in, reset accounts, change DNS or restore deleted mail.

## Subscription review timeline

After collecting local evidence, use `scripts/subscription_timeline.py` to combine
trace reports into a private CSV/JSON review worksheet. It preserves source hashes,
distinguishes unverified email dates from collection time, and leaves product/account
relationships blank for source-backed review. See [the timeline guide](docs/SUBSCRIPTION-TIMELINE.md).

```bash
python3 scripts/subscription_timeline.py --trace /path/to/private-report/trace.json --output /path/to/new-private-timeline
python3 -m unittest discover -s tests -v
```

```bash
python3 scripts/trace_exchange.py --evidence /path/to/invoice.eml --output /path/to/new-private-report
python3 -m unittest discover -s tests -p 'test_trace_exchange.py' -v
```

Keep real evidence and reports outside this public repository. Use fabricated examples
for code review. The existing offline mail-indexer proposal is separate and remains
unmerged; it requires a ZIP or directory of actual `.eml` files.
