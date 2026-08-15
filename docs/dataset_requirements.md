# Dataset Requirements and Sources

Target classes (Phase 1):
- DoS
- DDoS
- Port Scan
- Brute Force
- Web Attack
- Botnet
- Benign

## Primary Phase 1 datasets to download

The following datasets are the main sources you should collect for Phase 1. They are chosen for completeness, attack coverage, and common use in IDS research.

1. **CICIDS2017 / CSE-CIC-IDS2018**
   - Best all-in-one source for Phase 1.
   - Cover: `Benign`, `DoS`, `DDoS`, `Port Scan`, `Brute Force`, `Web Attack`, `Botnet`.
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

- CICIDS2017 / CSE-CIC-IDS2018: all Phase 1 attacks
- UNSW-NB15: DoS, DDoS, reconnaissance, normal, plus other attack classes
- CTU-13: botnet
- CICDDoS2019: DDoS / DoS
- NSL-KDD: DoS, Port Scan, Benign, U2R, R2L
- TON_IoT / Bot-IoT: IoT DoS/DDoS/reconnaissance
- CAIDA / MAWI: port scan / DDoS research

## Current data/phase1 status

The project currently contains the following confirmed raw dataset folders under `data/phase1/`:

- `data/phase1/CIC-IDS-2017/`
- `data/phase1/UNSW-NB15/`
- `data/phase1/CTU-13/`
- `data/phase1/NSL-KDD/`
- `data/phase1/Bot-IoT/`

Notes:

- `NSL-KDD` currently includes a duplicate nested copy under `data/phase1/NSL-KDD/nsl-kdd/`; keep one clean copy and remove duplicates after confirming the needed files.
- `UNSW-NB15` contains training/testing CSVs plus feature and label CSV exports.
- No `_Error.txt` placeholder files were found in the current `data/phase1/` dataset folders.
- `CICDDoS2019` and `TON_IoT` are not currently present, so add them if you need extra DDoS or IoT coverage.

Recommendation:

Keep raw dataset sources separate in `data/phase1/<dataset-name>/` until preprocessing, then move cleaned CSV/ARFF files into `ml/data/raw/` for feature extraction and model training.
