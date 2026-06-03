#!/bin/bash
#SBATCH --account=upftfg31_normal
#SBATCH --job-name=inspect
#SBATCH --output=logs/inspect_%j.out
#SBATCH --error=logs/inspect_%j.err
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=32
#SBATCH --partition=gpu
#SBATCH --gres=gpu:h100:1
#SBATCH --time=00:30:00
module load conda
conda activate unsloth_env
module load java/23.0.1
python inspect_rlvr.py
