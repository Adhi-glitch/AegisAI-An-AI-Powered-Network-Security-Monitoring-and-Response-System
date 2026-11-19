# AegisAI Phase 1 Attack Dataset Plan

## Project workflow
- Dataset
- Model
- Validation
- Actual network traffic
- Feature compatibility
- Real-time inference
- Threat correlation
- Explanation
- Response
- Dashboard

## Phase 1 attack categories
- DoS
- DDoS
- Port Scan
- Brute Force
- Web Attack
- Botnet
- Benign

## Next steps to start the project
1. Collect or place attack/benign data files into `data/phase1/<category>`.
2. Define dataset labels and schema for feature extraction.
3. Design the ML pipeline inside `ml/`, starting with data ingestion and training.
4. Plan the backend and database integration in `backend/` and `database/`.
5. Set up configuration, logging, and testing for the first phase.

## Notes
- The stage names you provided are workflow steps, not folder names.
- Focus for now is Phase 1 attacks and the dataset-to-model-to-validation path.
- Persisted alerts are restricted to the six non-benign Phase 1 classes when the model score is at least 0.50. Scores from 0.50 to 0.64 are low, 0.65 to 0.79 medium, and 0.80 or above high. Benign and below-threshold flows may appear transiently in the live traffic view but are not stored as alerts.
- Severity is a model-score band, not a calibrated probability or a guarantee that an event is malicious. The active evaluation split has capture overlap; independent real-world accuracy has not been established.
- A class appearing in the model bundle does not by itself establish live detection. The current live sensor has explicitly sourced packet indicators for port scans, high-rate TCP SYN traffic, repeated authentication-service connections, selected cleartext HTTP signatures, and optional local Botnet IOCs. These indicators are separate from model predictions; login outcomes, encrypted web content, and unlisted Botnet C2 require richer endpoint/application or threat-intelligence evidence. Validate from independently labeled captures before claiming live Phase 1 coverage.

## Week milestone update
See `docs/PROGRESS.md`. Dataset → Model → Validation → offline replay → thin explanation → dry-run response → minimal dashboard are implemented on the CICIDS sample path. Live traffic and advanced correlation remain later work.
