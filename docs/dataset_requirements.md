# Dataset Requirements and Sources

Target classes (Phase 1):
- Benign
- DoS
- DDoS
- Port Scan
- Brute Force
- Web Attack
- Botnet

## Canonical label mapping

The pipeline uses one ordered label set and numeric IDs: `0 Benign`, `1 Botnet`, `2 Brute Force`, `3 DDoS`, `4 DoS`, `5 Port Scan`, `6 Web Attack`. Unknown or generic binary labels such as `Attack`, `Malicious`, and `1` are dropped rather than guessed.

| Dataset | Original labels mapped to canonical classes | Exclusions and caveats |
|---------|---------------------------------------------|------------------------|
| CICIDS2017 | `BENIGN` → Benign; `DoS *` and `Heartbleed` → DoS; `DDoS` → DDoS; `PortScan` → Port Scan; `FTP-Patator` / `SSH-Patator` → Brute Force; `Web Attack *` (Brute Force, SQL Injection, XSS) → Web Attack; explicit `Bot` / `Botnet` → Botnet | `Infiltration` is not Botnet and is dropped. Rows in the checked-in Infiltration-named CSV that were previously rewritten to `Botnet` are excluded too. |
| CSE-CIC-IDS2018 | `Benign`; `Botnet`; `FTP-BruteForce` / `SSH-Bruteforce` → Brute Force; `DDoS *` → DDoS; `DoS *` → DoS; `PortScan` → Port Scan; `Brute Force -Web`, `Brute Force -XSS`, and `SQL Injection` → Web Attack | Infiltration is excluded. Treat each scenario/date Parquet file as an independent source group. TrafficForML exports lack source/destination port fields, so those normalized features are zero. |
| UNSW-NB15 | `Normal` → Benign; `DoS` → DoS; `Reconnaissance` → Port Scan | The canonical Port Scan class is a coarse reconnaissance bucket. Other UNSW attack categories are not forced into one of the seven labels. Use `attack_cat`, not the binary `label` column. |
| CTU-13 | `From-Normal` → Benign; `From-Botnet` / explicit Botnet → Botnet | Requires labeled flow exports under `data/phase1/CTU-13/`. |
| Bot-IoT | Explicit Benign/Normal → Benign; DoS/DDoS categories → their matching classes; Reconnaissance → Port Scan | The dataset name alone does not make a row Botnet. Requires labeled feature CSVs under `data/phase1/Bot-IoT/`. |
| NSL-KDD | `normal` → Benign; DoS family names (for example `neptune`, `smurf`) → DoS; `probe`, `ipsweep`, `nmap`, `portsweep` → Port Scan; `guess_passwd` → Brute Force | Remaining U2R/R2L and other attack labels are excluded unless a defensible mapping is added. |

Mapping code is centralized in `ml/data/multidataset.py` and shared by `scripts/normalize_cicids_labels.py`. Source category fields such as UNSW `attack_cat` take priority over generic binary fields.

## Primary Phase 1 datasets to download

The following datasets are the main sources you should collect for Phase 1. They are chosen for completeness, attack coverage, and common use in IDS research.

1. **CICIDS2017 / CSE-CIC-IDS2018**
   - Covers several Phase 1 classes; actual coverage must be checked after label normalization.
   - CICIDS2017 has explicitly labeled Bot traffic, but Web Attack coverage depends on the source CSV retaining its original attack labels.
   - Download the raw CSV flow exports and put them under `ml/data/raw/` or a dedicated `data/phase1/CICIDS2017/` folder.
   - Link: https://www.unb.ca/cic/datasets/ids-2017.html

2. **UNSW-NB15**
   - Good modern multi-class IDS dataset with normal and several attack types.
   - Cover: `Benign`, `DoS`, `DDoS`, `Reconnaissance`, `Backdoor`, `Worm`, `Analysis`, `Shellcode`, `Exploits`, and more.
   - Download the training/testing CSVs or raw PCAPs and place them in `data/phase1/UNSW-NB15/`.
   - Link: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/

3. **CTU-13**
   - Focused on botnet traffic and botnet/normal classification.
   - Cover: `Botnet`, `Benign`.
   - Use it for botnet-specific modeling and validation.
   - Link: https://www.stratosphereips.org/datasets-ctu13

4. **CICDDoS2019**
   - Focused on distributed denial-of-service attacks.
   - Cover: `DDoS`, `DoS`.
   - Good for strengthening DDoS/DoS detection performance.
   - Link: https://www.unb.ca/cic/datasets/dos.html

5. **NSL-KDD / KDD Cup 1999**
   - Classic IDS benchmark dataset.
   - Cover: `Benign`, `DoS`, `Probe` (Port Scan), `U2R`, `R2L`.
   - Use for quick experiments, label sanity checks, and feature compatibility work.
   - Link: https://www.unb.ca/cic/datasets/nsl.html

6. **TON_IoT or Bot-IoT**
   - Useful for IoT and network-based anomaly detection.
   - Cover: `DoS`, `DDoS`, `Reconnaissance`, `Benign`, `Backdoor`, and IoT-related attack scenarios.
   - Use this if your Phase 1 scope includes IoT-style traffic.
   - Link: https://ieee-dataport.org/open-access/toniot-datasets or https://research.unsw.edu.au/projects/bot-iot-dataset

7. **CAIDA / MAWI**
   - Research-grade raw traffic sources for port-scan and DDoS analysis.
   - Cover: `Port Scan`, `DDoS`, `Background traffic`.
   - Recommended only if you want raw PCAP and flow extraction work.
   - Links: https://www.caida.org, http://mawi.wide.ad.jp/mawi/

## Optional supporting datasets

- **DARPA / ADFA**: older IDS datasets for historical comparison.
- **ISCX2012 / ISCX2016**: extra labelled traffic for web and reconnaissance patterns.
- **MAWILab**: additional raw network traces for anomaly research.

## Dataset folder guidance

Use this structure for raw dataset organization:

- `data/phase1/CICIDS2017/`
- `data/phase1/UNSW-NB15/`
- `data/phase1/CTU-13/`
- `data/phase1/CICDDoS2019/`
- `data/phase1/NSL-KDD/`
- `data/phase1/TON_IoT/`
- `data/phase1/CAIDA/`

Then keep category-specific training examples under:

- `data/phase1/DoS/`
- `data/phase1/DDoS/`
- `data/phase1/Port Scan/`
- `data/phase1/Brute Force/`
- `data/phase1/Web Attack/`
- `data/phase1/Botnet/`
- `data/phase1/Benign/`

## What to download first

1. Download and prepare **CICIDS2017** or **CSE-CIC-IDS2018** first.
2. Download **UNSW-NB15** CSV or PCAPs next.
3. Download **NSL-KDD** for baseline prototyping.
4. Download **CTU-13** for botnet coverage.
5. Download **CICDDoS2019** for DDoS augmentation.
6. Add **TON_IoT or Bot-IoT** if you need IoT attack coverage.
7. Keep **CAIDA/MAWI** as optional raw traffic research sources.

## Completeness checklist

For each dataset you add, verify:
- The dataset files are full CSVs, ARFFs, or raw PCAPs — not placeholder `_Error.txt` files.
- Training and testing splits are included.
- Attack labels are available and mappable to Phase 1 targets.
- The data is stored in `data/phase1/<dataset-name>/` or `ml/data/raw/` for processing.
- Any dataset-specific schema is converted or mapped to `ml/data/feature_schema.py`.

## Notes for this project

- `NSL-KDD` is useful, but it does not cover modern web attack and botnet variants as well as CICIDS2017 or UNSW-NB15.
- `CICIDS2017` remains the strongest single source for Phase 1 coverage.
- Do not rely on incomplete or placeholder files; if a dataset directory contains only `_Error.txt` files, it is not ready to use.
- Keep raw dataset folders separate from category folders until you preprocess and label them.

## Example workflow

1. Place downloaded dataset files into `data/phase1/<dataset-name>/`.
2. Extract or convert the files into flow-level CSVs compatible with `ml/data/feature_schema.py`.
3. Place processed CSVs into `ml/data/raw/` if using `scripts/prepare_cicids.py`.
4. Run preprocessing and training:
    ```powershell
    python scripts\prepare_cicids.py --label-col Label --out ml/data/processed/combined.csv
    python ml\training\train.py
    python ml\evaluation\evaluate.py
    ```

## Quick mapping: dataset → attack coverage

- CICIDS2017 / CSE-CIC-IDS2018: Benign, DoS, DDoS, Port Scan, Brute Force, and explicit Bot labels; Web Attack only when the source subtypes are retained
- UNSW-NB15: DoS, DDoS, reconnaissance, normal, plus other attack classes
- CTU-13: botnet
- CICDDoS2019: DDoS / DoS
- NSL-KDD: DoS, Port Scan, Benign, U2R, R2L
- TON_IoT / Bot-IoT: IoT DoS/DDoS/reconnaissance
- CAIDA / MAWI: port scan / DDoS research

## Verified Workspace Coverage

The workspace now contains CIC-IDS-2017, CSE-CIC-IDS2018, UNSW-NB15, Bot-IoT, CTU-13, and NSL-KDD under `data/phase1/`. The streaming audit is reproducible with `python scripts/audit_phase1_coverage.py`. Counts below use the shared canonical mapper, exclude unsupported Infiltration labels, and omit overlapping NSL-KDD `KDDTest-21` and `KDDTrain+_20Percent` subsets.

| Canonical class | Retained rows | Conservative source groups |
|-----------------|--------------:|---------------------------:|
| Benign | 18,108,834 | 34 |
| Botnet | 409,074 | 15 |
| Brute Force | 109,220 | 3 |
| DDoS | 2,830,606 | 4 |
| DoS | 2,167,923 | 6 |
| Port Scan | 272,393 | 4 |
| Web Attack | 3,062 | 3 |

Group policy: CICIDS2017 day files, CSE-CIC-IDS2018 scenario/date Parquet files, and CTU-13 scenario Parquet files are separate capture groups. UNSW-NB15 official training/testing partitions, Bot-IoT `Full5pc` shards, and NSL-KDD official partitions each count as one source group unless capture provenance demonstrates otherwise. The Infiltration-named CICIDS file contributes its 288,566 Benign rows; Infiltration is not Botnet.

**Coverage verdict:** all seven labels have at least three conservative source groups, so the data now meets the minimum coverage prerequisite for a group-disjoint train/validation/test evaluation. This does not imply that model metrics pass the approved release thresholds or establish generalization to a deployment network.

The CSE-integrated strict group evaluation is recorded in
[`artifacts/strict_group_evaluation.json`](../artifacts/strict_group_evaluation.json).
Reproduce the deterministic 10,000-row-per-source-group/class evaluation with
`.\.venv\Scripts\python.exe scripts\evaluate_grouped_model.py`.
It used 573,986 bounded samples and held out 123,018 test rows with zero
source-group overlap. The model did not meet any approved attack-class
precision/recall gate, and benign false-alarm rate was 2.7928% versus the 0.5%
maximum. The test split has one source group for Brute Force, DDoS, DoS, Port
Scan, and Web Attack; these results do not qualify the active production bundle.
Its row-level Wilson intervals do not account for within-capture dependence.
The earlier six-class best-effort report is retained as historical evidence only:
[`artifacts/best_effort_group_evaluation.json`](../artifacts/best_effort_group_evaluation.json).
