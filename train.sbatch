#!/bin/bash
# Usage:
#   Submit job:       sbatch train.sbatch
#   Check status:     squeue -u $USER
#   Cancel job:       scancel <job_id>   (check logs first to see if it's failing)
#
#SBATCH --account=upftfg31_normal
#SBATCH --job-name=rlvr_devstral
#SBATCH --output=logs/training_%j.out
#SBATCH --error=logs/training_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=128G                 # Request enough RAM
#SBATCH --partition=gpu 
#SBATCH --gres=gpu:h100:1          # Request 1 GPU H100
#SBATCH --time=24:00:00

module load conda
conda activate unsloth_env
module load java/23.0.1
python training.py
