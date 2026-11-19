# Cluster checks

`verify_results.slurm` runs only the public aggregate verifier. It makes no model requests and reserves no GPU.

From the repository root on a Slurm cluster:

```bash
mkdir -p logs
sbatch hpc/verify_results.slurm
```

Model inference launchers will be added through the experiment issues. Keep account names, credentials, endpoint addresses and local storage paths in ignored local configuration. Hyperion/Slurm scripts may be published after this review.
