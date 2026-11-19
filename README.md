# FeSA LLM experiments

Test how prompt wording, demonstration count and label order affect LLM classification of phishing and malware feature records.

The completed pilot produced 800 responses from 200 distinct records. Phishing accuracy stayed at 50%; ransomware accuracy was 50% zero-shot and 75% / 66% with four balanced demonstrations under two label orders. These are exploratory results.

- [Pilot results and limits](docs/PILOT_V2.md)
- [Next experiment](docs/EXPERIMENT_PLAN.md)
- [Tracked issues](docs/ISSUES.md)
- [Experiment history](docs/HISTORY.md)
- [Publication boundary](docs/PUBLICATION.md)

The repository contains aggregate results and planning material. Original records, prompts containing real records, responses, embeddings, credentials and local infrastructure metadata stay private. The next experiment has not run.

Verify the public results offline:

```bash
python3 scripts/verify_baseline.py
python3 scripts/render_baseline.py --check
python3 -m unittest discover -s tests -v
python3 scripts/check_public_tree.py
```
