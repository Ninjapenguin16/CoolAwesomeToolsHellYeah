# RoostSweep

An AI-powered security log triage tool. RoostSweep reads security log entries and
uses a coding language model (Qwen Coder, or any OpenAI-compatible model) to classify
each entry as **BENIGN**, **SUSPICIOUS**, or **MALICIOUS**, with a severity
(1–5) and a one-sentence reason. It processes whole log files in batch and
can generate a detection rule from what it finds.

## What it does
- Classifies each log entry (BENIGN / SUSPICIOUS / MALICIOUS) with a 1–5 severity and a reason.
- Returns validated JSON and falls back to UNKNOWN when the model's reply can't be parsed.
- Processes a whole log file in batch with a small thread pool.
- Generates a detection rule (a Sigma rule by default) from the suspicious and malicious findings.
- Treats log text as untrusted input and uses a hardened prompt to resist prompt injection.
- Includes offline tests that use a fake model, so the parsing logic can be checked without a server.

## Files
| File | What it is |
|---|---|
| `RoostSweep.ipynb` | The tool (Jupyter notebook) |
| `triage_results.csv` / `triage_results.json` | Results from a 200-line run over a sample SSH auth log |
| `detection_rule.txt` | The Sigma rule Qwen Coder wrote from those results |

## Requirements
- Python 3.9 or newer
- The `openai` package (`pip install openai`)
- Access to an OpenAI-compatible model endpoint (a vLLM or GPUStack server, etc.)

## Setup
Install the one dependency:

```
pip install openai
```

Set your model endpoint and key as environment variables (never hard-code them):

```
export QWEN_BASE_URL="http://your-server/v1"
export QWEN_API_KEY="your-api-key"
```

If `QWEN_API_KEY` isn't set, the notebook asks for it with `getpass`, which hides it
and doesn't save it in the notebook.

## Usage
Open the notebook and run the cells top to bottom. Point `LOG_FILE` at a text file
with one log entry per line, and the tool will assess each one and save
`triage_results.csv`, `triage_results.json`, and `detection_rule.txt`.

## Security notes
- The API key is read at runtime (`getpass`) or from an environment variable; it is never stored in the notebook.
- Log data is treated as untrusted. The hardened prompt marks it as data and wraps it in `<<< >>>` delimiters, and the output is validated before it's trusted. No defense against prompt injection is perfect, so the tool never lets the model take actions.

## License
MIT. See the `LICENSE` file.
