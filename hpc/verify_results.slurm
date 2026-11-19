#!/bin/bash
#SBATCH --job-name=fesa-verify
#SBATCH --cpus-per-task=1
#SBATCH --mem=1G
#SBATCH --time=00:05:00
#SBATCH --output=logs/%x-%j.out
set -euo pipefail
cd "${SLURM_SUBMIT_DIR:?Submit this job from the repository root}"
python3 scripts/verify_baseline.py
