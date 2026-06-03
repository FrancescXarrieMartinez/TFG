import os
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_DATASETS_OFFLINE"] = "1"
import re, json, tempfile, subprocess, torch
from datasets import load_dataset
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

BASE = "/data/upftfg31/fxarrie/devstral-small-2507"
ADAPTER = "devstral-rlvr-d-lora"
PICK = ["cryptopals-17", "picoctf-magic", "cve-2019-12422", "cve-2010-2057"]
N_PER_GROUP = 1

tok = AutoTokenizer.from_pretrained(BASE)
if tok.pad_token is None: tok.pad_token = tok.eos_token
model = AutoModelForCausalLM.from_pretrained(BASE, dtype=torch.bfloat16, device_map="auto")
model = PeftModel.from_pretrained(model, ADAPTER)
model.eval()

ds = load_dataset("json", data_files="dataset.json", split="train")

def _extract_python_code(t):
    m = re.search(r'```python\s*\n(.*?)```', t, re.DOTALL); return m.group(1).strip() if m else None
def _states_vulnerable(t):
    l=t.lower()
    if re.search(r'\bnot\s+vulnerable\b', l): return False
    return bool(re.search(r'\bvulnerable\b', l))
def _check_syntax(c):
    try: compile(c,'<string>','exec'); return True
    except SyntaxError: return False
_SIG=[r'plaintext_b64',r'\bsys\.argv\b|\bargparse\b',r'[\^]|\bxor\b',r'\brange\(256\)']
def _check_oracle_api(c): return sum(1 for p in _SIG if re.search(p,c))>=3
def _count(p):
    try:
        with open(p) as f: return sum(1 for ln in f if ln.strip())
    except FileNotFoundError: return 0
def _valid(p):
    try:
        with open(p) as f: return any(json.loads(ln).get('valid') for ln in f if ln.strip())
    except (FileNotFoundError, json.JSONDecodeError): return False

def grade(entry, gen):
    out=entry["test_case_outputs"]; ins=entry["test_case_inputs"]
    rep={"verdict":out["verdict"]}
    if out["verdict"]=="NOT_VULNERABLE":
        rep["branch"]="NOT_VULN"; rep["score"]="(text-scored)"; return rep
    rep["states_vulnerable"]=_states_vulnerable(gen)
    code=_extract_python_code(gen)
    rep["code_extracted"]=bool(code)
    if not code: rep["score"]=0.0; return rep
    rep["syntax_ok"]=_check_syntax(code)
    rep["oracle_api"]=_check_oracle_api(code)
    enc=subprocess.run([ins["php_bin"],ins["oracle_path"],"encrypt",ins["plaintext"],ins["key"]],
                       capture_output=True,text=True,timeout=10)
    ct=json.loads(enc.stdout)["ciphertext"]
    f=tempfile.NamedTemporaryFile(mode='w',suffix='.py',delete=False,dir='/tmp'); f.write(code); f.close()
    log=tempfile.mktemp(suffix='_oracle.log',dir='/tmp')
    so=''
    try:
        r=subprocess.run(['python3',f.name,ins["oracle_path"],ins["key"],ct],
                         env={**os.environ,'ORACLE_LOG':log},capture_output=True,timeout=180)
        so=r.stdout.decode('utf-8',errors='replace') if r.stdout else ''
    except subprocess.TimeoutExpired as e:
        so=(e.stdout or b'').decode('utf-8',errors='replace') if isinstance(e.stdout,bytes) else (e.stdout or '')
    tc=_count(log); fv=_valid(log); pt=ins["plaintext"]
    rep["total_calls"]=tc; rep["found_valid"]=fv
    rep["plaintext_in_stdout"]= pt in so.strip()
    rep["stdout_head"]=so.strip()[:500]
    if pt in so.strip() and tc>=256: rep["score"],rep["tier"]=1.0,"1.0 genuine"
    elif pt in so.strip(): rep["score"],rep["tier"]=0.2,"0.2 CAPPED (match, <256 calls)"
    elif tc>=256 and fv: rep["score"],rep["tier"]=0.5,"0.5"
    elif tc>=200: rep["score"],rep["tier"]=0.2,"0.2"
    else: rep["score"],rep["tier"]=(0.2 if rep["oracle_api"] else 0.1),"static"
    rep["EXPLOIT_SOURCE"]=code
    os.unlink(f.name)
    if os.path.exists(log): os.unlink(log)
    return rep

for gid in PICK:
    subset=[e for e in ds if e["group_id"]==gid][:N_PER_GROUP]
    for entry in subset:
        prompt=tok.apply_chat_template([{"role":"user","content":entry["prompt"]}],
                                       tokenize=False, add_generation_prompt=True)
        ids=tok(prompt,return_tensors="pt").to(model.device)
        with torch.no_grad():
            g=model.generate(**ids,max_new_tokens=1024,do_sample=True,temperature=1.0,top_p=1.0)
        gen=tok.decode(g[0][ids.input_ids.shape[1]:],skip_special_tokens=True)
        print("="*90); print("ENTRY:",gid); print("--- GENERATED COMPLETION ---"); print(gen)
        print("--- REWARD BREAKDOWN ---"); print(json.dumps(grade(entry,gen),indent=2))
