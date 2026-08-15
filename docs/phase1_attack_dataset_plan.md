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

## Week milestone update
See `docs/PROGRESS.md`. Dataset → Model → Validation → offline replay → thin explanation → dry-run response → minimal dashboard are implemented on the CICIDS sample path. Live traffic and advanced correlation remain later work.
