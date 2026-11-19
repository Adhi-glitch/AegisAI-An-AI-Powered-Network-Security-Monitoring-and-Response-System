# Presentation Prototype Progress and Evaluation History

Last updated: 2026-11-18

## Current release-gate status

- CSE-CIC-IDS2018 is integrated in dataset label normalization, Parquet loading, bounded sampling, source-group auditing, and strict evaluation.
- The coverage audit finds at least three conservative source groups for each canonical class.
- The strict evaluation used 573,986 bounded samples and held out 123,018 test rows with zero group overlap. All six attack classes missed the approved precision/recall gates; benign false-alarm rate was 2.7928% against the 0.5% maximum.
- The evaluation trained an in-memory model and did not update the active production bundle. The test split has one source group each for Brute Force, DDoS, DoS, Port Scan, and Web Attack. Wilson intervals are row-level, not capture-cluster adjusted. See `artifacts/strict_group_evaluation.json`.
- Latest full backend test suite (2026-11-17): 167 passed and one PostgreSQL test skipped without `AEGIS_TEST_POSTGRES_URL`.

## Historical row-random prototype snapshot (2026-10-08)

- The supplied `data/phase1/` datasets contain examples for all seven canonical classes.
- `scripts/build_prototype_dataset.py --rows-per-group-class 10000 --seed 42` produced a bounded 413,104-row sample and retained each row's conservative source-group ID.
- `scripts/prepare_prototype_splits.py --sample-size 250000 --seed 42` created train/validation/test partitions using the explicit prototype row-split mode. Metadata flags capture overlap.
- A 7-class CPU RandomForest with 120 trees is active at `ml/models/multi_dataset_bundle/` and uses the same 12 ordered numeric features as live flow extraction. Capture startup rejects bundles with a different feature schema.
- `artifacts/test_report.json` was regenerated from the active bundle: 82,621 test rows and 94.9178% accuracy, with per-class precision, recall, F1, support, confusion matrix, and one-vs-rest FPR.
- The 94.92% result is **exploratory only**: rows from a capture can appear in multiple partitions. Do not present it as independent-capture generalization.
- Live IPv4 flow aggregation, admin-only start/stop/status/interface routes, database persistence, WebSocket broadcast, and Jinja dashboard controls are implemented. Interface listing returns Scapy-resolvable names and accepts NPF device-path aliases.
- FastAPI serves the Jinja homepage at `/`, Jinja sign-in at `/signin`, and the Jinja live dashboard at `/dashboard` (`/legacy` is an alias). The separate React/Vite console is served at `/console` after its frontend build.

## Verification

- Tests cover all-class held-out prototype inference, reordered/missing/non-finite features, bundle failures/parity, grouped split behavior, flow aggregation, capture lifecycle, admin-only routes, and real-model API persistence.
- Full test suite: 48 passed, with 46 Scapy cryptography and pandas categorical deprecation warnings.
- Scapy reports `conf.use_pcap=True` and enumerates interfaces on this Windows host. Actual sniffing is not verified: this process is not elevated and a loopback probe captured zero packets. Run the smoke test from elevated PowerShell and confirm packet/flow counts before claiming live capture.
- Firewall prevention remains dry-run.

## Remaining limitations

- The later CSE-CIC-IDS2018 integration and strict evaluation are summarized in the current release-gate section above. This older prototype snapshot and row-random report are historical, not independent generalization evidence.
- Prototype flow features cover IPv4 bidirectional packet/byte totals, rates, ports, duration, and protocol; they are not complete CICFlowMeter-equivalent statistics.
- Npcap is available, but actual packet capture still needs verification from an elevated process. Current automated tests use synthetic packets.

## Reproduce the prototype

```powershell
python scripts\build_prototype_dataset.py --rows-per-group-class 10000 --seed 42
python scripts\prepare_prototype_splits.py --sample-size 250000 --seed 42
python -m ml.training.train --splits-dir ml/data/splits/prototype --bundle-dir ml/models/multi_dataset_bundle --engine random_forest --n-estimators 120
python -m ml.evaluation.evaluate
python -m pytest -q
```

Restart the backend after training so its model cache loads the newly active bundle. Live capture needs Npcap/libpcap and suitable OS privileges; verify it only on an authorized interface. After starting `python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000 --reload`, the Jinja homepage is at `http://127.0.0.1:8000/`, live-capture controls are at `http://127.0.0.1:8000/dashboard`, and the React console is at `http://127.0.0.1:8000/console` after building the frontend.