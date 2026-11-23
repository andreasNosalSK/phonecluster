# Workloads & Automation Cookbook

PhoneCluster turns all your phones into one unified pool for parallel scripts, compiling, local AI, and smart-home automation.

---

## 1. Parallel Scripts & Batch Jobs (`pc map`)

### Run a file of shell commands across all cool, ready phones
Create `jobs.txt` (one command per line; `#` lines ignored):
```bash
echo "Task A on $PHONECLUSTER_NODE_ID"
python3 -c "print(sum(range(5_000_000)))"
ffmpeg -i input1.mp4 -c:v libx264 out1.mp4
```
Dispatch across the entire cluster with automatic thermal throttling & failover:
```bash
pc map --jobs-file jobs.txt --retries 2 --output-jsonl results.jsonl
```

### Ship & run a local Python or Bash script (zero manual `scp`!)
Edit your script once on the Master phone (or paste it in the Web Control Center → **2. Run & Parallel Jobs**):
```bash
pc map \
  --script examples/sample_job.py \
  --args-file examples/sample_args.txt \
  --output-jsonl prime_results.jsonl
```
Every job automatically receives two environment variables:
- `PHONECLUSTER_NODE_ID` (e.g. `node0`, `node1`, `node2`)
- `PHONECLUSTER_TASK_INDEX` (`0`, `1`, `2`, ...)

---

## 2. Distributed C/C++ Compiler PC (`distcc`)

Make sure every phone runs the same `clang` version (`pkg install clang distcc` on Termux or `apt install clang distcc` on Debian 13).

1. Start `distccd` across all ready phones in one command (or click **Start All** in Web UI → **Workloads**):
   ```bash
   pc run --target all "bash ~/phonecluster/scripts/05_workload_helpers.sh distcc-start 192.168.1.0/24"
   ```
2. Dynamically export `DISTCC_HOSTS` containing **only** currently cool, healthy phones:
   ```bash
   eval "$(pc distcc-env)"
   echo "$DISTCC_HOSTS"
   make -j16 CC="distcc clang" CXX="distcc clang++"
   ```

---

## 3. Local AI (`llama.cpp` — Data Parallel vs. RPC Pooling)

### Fastest on 4 GB phones: Data-Parallel Compact Models
Because LLM decode speed is memory-bandwidth bound (~7–9.5 GB/s effective CPU decode on older LPDDR4X phones), running compact quantized models **independently per phone** gives far higher total throughput than splitting one large model over Wi-Fi:
- `Qwen2.5-1.5B-Instruct Q4_K_M` (~1.1 GB RAM, ~6.4–8.6 tok/s per phone)
- `Gemma 4 E2B` (~1.4 GB RAM)
- `Llama 3.2 3B Q4_0` (~2.0 GB RAM, ~3.5–4.8 tok/s per phone)

Use `pc map` to process batches of prompts across all 3 phones concurrently!

### Pooling RAM Across Phones (`llama.cpp` RPC)
When a 7B–8B model won't fit on one 4 GB phone:
1. Compile `llama.cpp` with `-DGGML_RPC=ON` on each phone:
   ```bash
   git clone https://github.com/ggml-org/llama.cpp ~/llama.cpp
   cmake -S ~/llama.cpp -B ~/llama.cpp/build -DGGML_RPC=ON
   cmake --build ~/llama.cpp/build -j
   ```
2. Start RPC workers across all ready phones:
   ```bash
   pc run --target all "bash ~/phonecluster/scripts/05_workload_helpers.sh llama-rpc-start ~/llama.cpp 50052"
   ```
3. Run inference from the Master using only healthy RPC workers:
   ```bash
   RPC_FLAG="$(pc llama-rpc)"
   ~/llama.cpp/build/bin/llama-cli -m model-q4_k_m.gguf ${RPC_FLAG} -p "Summarize distributed computing."
   ```

---

## 4. OpenMPI Parallel Computing

```bash
pc mpi-hostfile -o ~/hosts.mpi
mpirun --hostfile ~/hosts.mpi -np 16 ./my_mpi_program
```

---

## 5. Automated 24/7 Battery Guard Webhook (Home Assistant / Smart Plug)

For unrooted Termux phones running 24/7, set `safety.battery_webhook_url` in `config/cluster.json`:

```json
"safety": {
  "max_temp_c": 40.0,
  "resume_temp_c": 37.0,
  "battery_low_pct": 45,
  "battery_high_pct": 60,
  "battery_webhook_url": "http://192.168.1.201:8123/api/webhook/phonecluster_battery"
}
```

PhoneCluster posts a JSON payload whenever a phone crosses `60%` while charging (`event: "charge_off"`), drops below `45%` while discharging (`event: "charge_on"`), or hits thermal throttling (`event: "thermal_throttle"`):

```json
{
  "event": "charge_off",
  "node_id": "node1",
  "message": "Battery at 62% (CHARGING) >= 60%. Cut charger power...",
  "battery_pct": 62,
  "battery_status": "CHARGING",
  "temp_c": 34.2,
  "timestamp": 1795450000
}
```

### Example Home Assistant Automation (Toggle Wi-Fi Smart Plug)
```yaml
alias: PhoneCluster 24/7 Battery Guard
trigger:
  - platform: webhook
    webhook_id: phonecluster_battery
    local_only: true
action:
  - choose:
      - conditions: "{{ trigger.json.event == 'charge_off' }}"
        sequence:
          - service: switch.turn_off
            target:
              entity_id: switch.phonecluster_charger_plug
      - conditions: "{{ trigger.json.event == 'charge_on' }}"
        sequence:
          - service: switch.turn_on
            target:
              entity_id: switch.phonecluster_charger_plug
```
