# Padding Oracle Vulnerability Detection with a Fine-Tuned LLM

This repository contains the dataset, training code, and evaluation harness for the
TFG *"Padding Oracle Vulnerability Detection in Source Code Using a Fine-Tuned Large
Language Model."* The full write-up is in
[`Padding_Oracle_Vulnerability_Detection_in_Source_Code_Using_Fine_Tuned_Large_Language_Model.pdf`](Padding_Oracle_Vulnerability_Detection_in_Source_Code_Using_Fine_Tuned_Large_Language_Model.pdf).

The goal of the project: take a code-specialised model (**Devstral Small 2507**, 24B
parameters) and fine-tune it, in two stages, so that given a snippet of cryptographic
code it can (1) decide whether the code has a **padding oracle** vulnerability and
(2) if it does, write a Python **exploit that actually recovers the plaintext** by
talking to the real code.

This README explains, step by step, how to reproduce every result.
---

## 1. What is in this repository

| Path | What it is |
|---|---|
| `dataset.json` | The 45-entry dataset. Every entry has a `prompt`, the `test_case_inputs` (how to run the oracle) and the `test_case_outputs` (the correct answer). This is the single input to all training and evaluation. |
| `data/metadata.jsonl` | One line per entry: id, group, source (real CVE / CTF / synthetic), language, label. Bookkeeping only. |
| `data/sft_targets/` | The **reference answers**. For vulnerable entries, a working Python exploit (`*.py`); for safe entries, the expected explanation (`*.txt`). SFT learns to reproduce these. |
| `sft_training.py` | Stage 1: supervised fine-tuning (SFT). Produces the `devstral-sft-lora/` adapter. |
| `training.py` | Stage 2: GRPO reinforcement learning with a verifiable reward. Produces `devstral-rlvr-c-lora/` (from base) or `devstral-rlvr-d-lora/` (from the SFT adapter). |
| `evaluate.py` | Evaluates any of the four configurations on the held-out test set and writes `eval_results_*.json`. |
| `inspect_rlvr.py` | Prints a few full model completions plus the reward breakdown, for manual inspection. |
| `*.sbatch` | SLURM job scripts that run the above on the cluster. |
| `cve-*/`, `cryptopals*/`, `picoctf_magic/`, `ctf-*/`, `prestashop-CVE4/` | One directory per source. Each holds the vulnerable (and patched) code plus its **oracle adapter** — the small program that wraps the code in a uniform command-line interface. |
| `synthetic_data/` | The batches of synthetic entries generated from the real seeds, with the spec used to make them. |
| `logs/`, `eval_results_*.json`, `diagnostics/` | The actual run logs and result files from the thesis. You can compare your reproduction against these. |

### The dataset entry format

Each entry in `dataset.json` looks like this:

```json
{
  "group_id": "cryptopals-17",
  "prompt": "You are a security researcher ... <source code> ... classify and exploit",
  "test_case_inputs": {
    "php_bin":      "python3",
    "oracle_path":  "cryptopals17/oracle_adapter.py",
    "key":          "<per-entry key>",
    "plaintext":    "<per-entry plaintext>"
  },
  "test_case_outputs": {
    "verdict":            "VULNERABLE",
    "expected_plaintext": "<same plaintext, or null when safe>"
  }
}
```

- `php_bin` is the program that runs the adapter. It is **`python3`** for Python cases,
  the **PHP interpreter path** for the PrestaShop case, and the **compiled `oracle`
  binary/launcher** for the C and Java cases. (The name is historical — it is not always PHP.)
- `oracle_path` is the adapter on disk.
- The harness first calls `php_bin oracle_path encrypt <plaintext> <key>` to get a
  ciphertext, then runs the exploit, which repeatedly calls
  `php_bin oracle_path decrypt <ciphertext> <key>` and reads back a single
  valid/invalid bit per query.

### The four configurations

Every result compares the same base model with four different adapters on top:

| Config | Adapter | Training |
|---|---|---|
| **A** | none | base Devstral, no fine-tuning |
| **B** | `devstral-sft-lora` | SFT only |
| **C** | `devstral-rlvr-c-lora` | GRPO only (from base) |
| **D** | `devstral-rlvr-d-lora` | SFT, then GRPO (the full pipeline) |

The test set is fixed in code: the two real CVE groups **`cve-2016-0736`** (C) and
**`prestashop-CVE4`** (PHP), four entries in total (two vulnerable, two safe). Everything
else is training data. This split is hard-coded as `TEST_GROUP_IDS` in
`sft_training.py`, `training.py`, and `evaluate.py`, so a rerun always uses the same split.

---

## 2. Environment

The thesis ran everything on a single **NVIDIA H100 (80 GB)** GPU on the **Pirineus**
cluster (CSUC), with jobs submitted through **SLURM**.

You need:

- **Python** with `torch`, `transformers`, `peft`, `trl`, and `datasets` (the cluster
  used a conda environment named `unsloth_env`).
- A local copy of the **base model**, Devstral Small 2507. The code loads it in offline
  mode from an absolute path (`/data/upftfg31/fxarrie/devstral-small-2507`).
- Tools to build the oracle adapters: **`gcc`** (C case), a **JDK** (Java cases — the
  cluster used `java/23.0.1`), a **PHP** interpreter (PrestaShop case), and **`pycryptodome`**
  for the Python exploits.

> **You must edit two cluster-specific paths to run this anywhere else:**
> 1. `MODEL_NAME` / `model_name` at the top of `sft_training.py`, `training.py`, and
>    `evaluate.py` → point it at your local Devstral Small 2507.
> 2. The `php_bin` for the `prestashop-CVE4` entries in `dataset.json` → point it at
>    your `php` binary. (All other `php_bin` values are `python3` or a relative path and
>    need no change.)

Clone the repository and `cd` into it; all commands below assume the repository root is
the working directory.

---

## 3. Build the oracle adapters

The Python and PHP adapters run as-is. The **C and Java adapters must be compiled first**
(the compiled artifacts are git-ignored, so they are not in the repo). Run `make` in each
`vulnerable/` and `patched/` directory:

```sh
# C case (CVE-2016-0736) — needs gcc
(cd cve-2016-0736/vulnerable && make)
(cd cve-2016-0736/patched   && make)

# Java cases (CVE-2019-12422, CVE-2010-2057, CVE-2010-3300) — need a JDK
(cd cve-2019-12422/vulnerable && make)
(cd cve-2019-12422/patched    && make)
(cd cve-2010-2057/vulnerable  && make)
(cd cve-2010-2057/patched     && make)
(cd cve-2010-3300/vulnerable  && make)
(cd cve-2010-3300/patched     && make)
```

Each build produces an executable `oracle` launcher in its directory. Once built, you can
test any adapter by hand:

```sh
# encrypt a message (random IV each time):
cve-2016-0736/vulnerable/oracle x encrypt "SensitiveData!1" "MySecretKey12345"
#   -> {"status": "success", "ciphertext": "<base64...>"}

# decrypt it (this is the oracle): empty plaintext_b64 = padding/decrypt failed
cve-2016-0736/vulnerable/oracle x decrypt "<ciphertext>" "MySecretKey12345"
#   -> {"status": "success", "plaintext_b64": "<base64 or empty>"}
```

Each case directory has its own `README.md` with the details of that specific CVE.

---

## 4. (Optional but recommended) Check that every entry's adapter works

This reproduces the **dynamic smoke test** that every entry passed before entering the
dataset: for each **vulnerable** entry the project's reference exploit must recover the
plaintext through the oracle, and for each **safe** entry the attack must fail. It is the
fastest way to confirm your adapters are built and runnable before you spend GPU hours.

Save this as `verify_entries.py` in the repository root:

```python
"""Smoke-test each dataset entry's adapter with the project's reference exploit."""
import os, sys, json, subprocess, tempfile

def sft_target(gid, verdict):
    suffix = "vuln" if verdict == "VULNERABLE" else "safe"
    ext = "py" if verdict == "VULNERABLE" else "txt"
    for c in [f"data/sft_targets/{gid}-{suffix}.{ext}", f"data/sft_targets/{gid}.{ext}"]:
        if os.path.exists(c):
            return c
    return None

only = set(sys.argv[1:])  # optional: pass group_ids to check just those
for i, e in enumerate(json.load(open("dataset.json"))):
    gid, ti, to = e["group_id"], e["test_case_inputs"], e["test_case_outputs"]
    if only and gid not in only:
        continue
    if to["verdict"] != "VULNERABLE":
        print(f"[{i}] {gid:18} SAFE  -> verdict-only, no exploit to run")
        continue
    exploit = sft_target(gid, "VULNERABLE")
    enc = subprocess.run([ti["php_bin"], ti["oracle_path"], "encrypt", ti["plaintext"], ti["key"]],
                         capture_output=True, text=True, timeout=15)
    try:
        ct = json.loads(enc.stdout)["ciphertext"]
    except Exception:
        print(f"[{i}] {gid:18} ENCRYPT FAILED: {enc.stderr[:120]}"); continue
    log = tempfile.mktemp(suffix="_oracle.log", dir="/tmp")
    r = subprocess.run(["python3", exploit, ti["oracle_path"], ti["key"], ct],
                       env={**os.environ, "ORACLE_LOG": log}, capture_output=True, timeout=180)
    out = (r.stdout or b"").decode("utf-8", "replace").strip()
    calls = sum(1 for _ in open(log)) if os.path.exists(log) else 0
    ok = ti["plaintext"] in out
    print(f"[{i}] {gid:18} {'OK  ' if ok else 'FAIL'} recovered={ok} oracle_calls={calls}")
    if os.path.exists(log):
        os.unlink(log)
```

Run it:

```sh
# Check everything (slow — each padding-oracle attack makes thousands of queries):
python3 verify_entries.py

# Or check a single group while you set things up:
python3 verify_entries.py cryptopals-17
```

An `OK` line with `oracle_calls` in the hundreds-to-thousands means the adapter and the
reference exploit work end to end. (`oracle_calls` of 0 or 1 would mean the attack was
skipped, not run — the reward harness in §6 rejects those exactly for this reason.)

> **Note on the oracle log.** The exploit records one JSON line per oracle query in the
> file named by the `ORACLE_LOG` environment variable. The verification snippet, the
> training reward, and the evaluation harness all set this variable and count the lines —
> this is how "did the model perform a real attack" is decided.

You can also verify the dataset is internally consistent:

```sh
# 45 entries in dataset.json, 44 lines in metadata.jsonl (it has no trailing newline):
python3 -c "import json;print(len(json.load(open('dataset.json'))),'entries')"
wc -l data/metadata.jsonl
```

---

## 5. Stage 1 — Supervised fine-tuning (Config B)

SFT teaches the model the **answer format**: announce `VULNERABLE.` (or
`NOT VULNERABLE.`) first, then, for vulnerable entries, a fenced Python exploit. It trains
on the 41 training entries for 3 epochs and saves a LoRA adapter to `devstral-sft-lora/`.

On the cluster:

```sh
sbatch sft_train.sbatch
```

Or directly (on a machine with the GPU and environment):

```sh
python sft_training.py
```

This runs in a few minutes and produces `devstral-sft-lora/`. That adapter is **Config B**,
and it is also the starting point for Config D.

---

## 6. Stage 2 — GRPO reinforcement learning (Configs C and D)

GRPO refines the model so its exploits actually run. The reward in `training.py` is
**verifiable**: for each generated exploit it extracts the Python block, checks it
compiles, runs it against the real oracle adapter with a fresh ciphertext and a query log,
and assigns a tier:

| Tier | Vulnerable entry |
|---|---|
| `0.0` | no verdict / no code block / does not compile |
| `0.1` | compiles |
| `0.2` | shows the oracle-API signals, or makes ≥ 200 real oracle calls |
| `0.5` | ≥ 256 logged queries **and** at least one valid-padding response |
| `1.0` | prints the recovered plaintext **and** made ≥ 256 logged queries |

(The ≥ 256-query floor is what stops the model from "cheating" — e.g. decrypting with the
key directly — from earning full credit. Safe entries are scored on the explanation
instead: `1.0` for a correct verdict that names ≥ 2 integrity concepts, `0.5` for one
that names fewer, `0.0` for a wrong/missing verdict.)

Both configurations are controlled by two environment variables that the sbatch files set
for you:

- **Config C (GRPO only, from the base model):**

  ```sh
  sbatch train.sbatch
  ```
  This sets `RLVR_OUTPUT_DIR=devstral-rlvr-c-lora` and leaves `SFT_ADAPTER_PATH` unset, so
  GRPO starts from a fresh adapter. Output: `devstral-rlvr-c-lora/`.

- **Config D (SFT, then GRPO — the full pipeline):**

  ```sh
  sbatch train_full.sbatch          # run AFTER sft_train.sbatch has finished
  ```
  This sets `SFT_ADAPTER_PATH=devstral-sft-lora` and
  `RLVR_OUTPUT_DIR=devstral-rlvr-d-lora`, so GRPO continues from the SFT adapter. Output:
  `devstral-rlvr-d-lora/`.

To run without SLURM, set the same variables yourself:

```sh
# Config C
RLVR_OUTPUT_DIR=devstral-rlvr-c-lora python training.py
# Config D
SFT_ADAPTER_PATH=devstral-sft-lora RLVR_OUTPUT_DIR=devstral-rlvr-d-lora python training.py
```

GRPO trains for 200 steps with a fixed seed (42). On one H100 the GRPO-only run took about
4.7 hours and the SFT→GRPO run about 8.5 hours. Live reward is printed in
`logs/training_*.out` / `logs/rlvr_d_*.out`.

---

## 7. Evaluation

`evaluate.py` loads the four held-out entries, generates a completion for each, scores it
with the same reward harness as training, and writes a results file with per-entry detail
and the aggregate metrics (accuracy, precision, recall, F1, exploit-generation rate,
syntactic-validity rate, exploit success rate, reward-tier distribution).

Run each configuration:

```sh
sbatch evaluate.sbatch A    # base model      -> eval_results_A.json
sbatch evaluate.sbatch B    # SFT             -> eval_results_B.json
sbatch evaluate.sbatch C    # GRPO only       -> eval_results_C.json
sbatch evaluate.sbatch D    # SFT then GRPO   -> eval_results_D.json
```

Or directly:

```sh
python evaluate.py --config D
```

### Greedy vs. sampled

The thesis reports two passes per configuration:

- **Greedy** (default, `--mode greedy`): one deterministic completion per entry. These are
  the headline numbers in the report — anyone rerunning gets the same figures. Output:
  `eval_results_<config>.json`.
- **Sampled** (`--mode sample`): draws `k = 5` completions per entry at a fixed temperature
  and seed, and reports the fraction that succeed, to show whether a result is luck or a
  real property of the model. Output: `eval_results_<config>_sample.json`.

```sh
python evaluate.py --config D --mode greedy
python evaluate.py --config D --mode sample
```

The committed `eval_results_*.json` and `eval_results_*_sample.json` files are the exact
outputs from the thesis runs, so you can diff your reproduction against them. The headline
findings to expect:

- **Detection.** Configs **B** and **D** classify all four held-out entries correctly
  (accuracy / F1 = 1.0). Config **C** over-flags one safe entry (F1 = 0.80). Config **A**
  (base) is at chance (F1 = 0.50).
- **Exploitation.** B and D generate a parseable, compiling exploit every time
  (generation and syntactic-validity rate = 1.0), but on these two unseen CVEs the
  generated exploits reach the oracle without recovering the plaintext (success rate =
  0.0, reward tier 0.2). A and C generate no exploit at all.

---

## 8. Inspecting and diagnosing results

- **`inspect_rlvr.py`** prints the full generated completion plus a detailed reward
  breakdown for one entry per chosen group, so you can read exactly what the model wrote
  and why it scored what it did:

  ```sh
  sbatch inspect.sbatch        # or: python inspect_rlvr.py
  ```

- **`diagnostics/exploit_failure_analysis.txt`** is the diagnostic transcript for the two
  held-out CVEs. It shows that (a) the hand-written reference exploits recover the
  plaintext on both CVEs (so the targets and harness work), (b) the model's generated
  exploits fail as-is, and (c) fixing only the one diagnosed plumbing defect per CVE makes
  the model's *own* exploit recover the plaintext. This is the evidence behind the
  qualitative analysis in the report: the model gets the Vaudenay attack logic right and
  fails only on the target-specific wire-format plumbing.

---

## 9. End-to-end summary

```sh
# 0. Edit MODEL_NAME (3 files) and the prestashop php_bin in dataset.json.

# 1. Build the C and Java oracle adapters.
(cd cve-2016-0736/vulnerable && make) && (cd cve-2016-0736/patched && make)
# ...repeat for the cve-2019-12422, cve-2010-2057, cve-2010-3300 vulnerable/ and patched/ dirs.

# 2. (Optional) Check the adapters end to end.
python3 verify_entries.py cryptopals-17

# 3. Train.
sbatch sft_train.sbatch        # -> devstral-sft-lora      (Config B)
sbatch train.sbatch            # -> devstral-rlvr-c-lora   (Config C)
sbatch train_full.sbatch       # -> devstral-rlvr-d-lora   (Config D, after SFT)

# 4. Evaluate.
for c in A B C D; do sbatch evaluate.sbatch $c; done

# 5. Read eval_results_*.json and compare against the committed files.
```

For the full background — what a padding oracle is, why the dataset is built this way, and
how to read the results — see the PDF report at the top of the repository.
