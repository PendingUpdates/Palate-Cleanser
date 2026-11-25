# Palate Cleanser: synthetic audit planner

This separate Python experiment reads supplied synthetic inventory and emits a JSON review plan. It does not scan a host, detect real PUPs, remove anything, or establish that a system is clean. Only the reserved fake product `org.example.audit-fixture-browser` has a rule; all real products remain unsupported.

## Run

Python 3 standard library only; no package installation or administrator access required. Run from this directory:

```sh
python3 -B audit_candidate.py
python3 -B audit_candidate.py --inventory-stdin < examples/owned-fixture.json
python3 -B -m unittest discover -s tests -v
```

No-input mode emits an empty report, not a clean-host verdict. Supplied-input mode reads JSON from stdin only. Output goes to stdout; there are no file, registry, process, network, elevation or removal adapters. Every proposal is for human review, and `changes` remains empty. Exit 0 may include skips. Unsupported arguments fail with exit 2.

Fixtures supply unverified claims, not live ownership evidence. Missing, ambiguous, shared or conflicting ownership is skipped. Real-product rules, Windows collectors and removal remain unimplemented in this planner. Do not import or execute the legacy PowerShell scripts for this workflow.

## Scope and compatibility

This addition does not change the legacy remover, its interfaces or product version. Root legacy entry points now fail closed; archived legacy source remains unsafe and is not exercised by these tests. No repository rename, release certification, Windows test or Proxmox test is claimed.
