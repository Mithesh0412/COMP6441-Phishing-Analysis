# COMP6441-Phishing-Analysis
COMP6441 project - a comparative content analysis of human-written and LLM-generated phishing emails, examining both technical indicators (URLs, domain spoofing, sender anomalies) and psychological manipulation tactics (authority, urgency, personalisation, reward framing).

## Dataset

This project uses the **Human-LLM generated phishing-legitimate emails** dataset by Francesco Greco, available on Kaggle:
https://www.kaggle.com/datasets/francescogreco97/human-llm-generated-phishing-legitimate-emails

The dataset is not included in this repository - download it separately and place the CSV files in the paths expected by `extract_features.py`, or update the paths in the script's `main()` call.

## Files

| File | Description |
|---|---|
| `extract_features.py` | Main analysis script. Loads both phishing email sets, extracts technical and psychological indicators from each email, and outputs comparative statistics. |
| `phishing_analyser.html` | Standalone interactive tool (no dependencies, runs in any browser). Paste a single email and sender address to see an annotated breakdown of detected manipulation cues and a risk classification. Built using the same detection logic as the Python script, for live demonstration and manual validation purposes. |
| `features_human.json` | Extracted features for the sampled human-generated phishing emails. |
| `features_llm.json` | Extracted features for the sampled LLM-generated phishing emails. |
| `comparison_summary.json` | Aggregate comparative statistics between the two groups. |
| `case_study_candidates_human.json` | Top 5 human-generated emails ranked by deception score, used to select case studies. |
| `case_study_candidates_llm.json` | Top 5 LLM-generated emails ranked by deception score, used to select case studies. |

## Running the analysis

```bash
# Create and use a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the required modules to run the analysis
pip install -r requirements.txt

# Run the analysis to get the 5 json files as output
python extract_features.py
```

By default, the script expects:
- `human-generated/phishing.csv` (columns: `sender, receiver, date, subject, body, urls, label`)
- `llm-generated/phishing.csv` (columns: `text, label`)

These datasets are available from the kaggle link attached above.

## Using the interactive tool

Open `phishing_analyser.html` directly in any browser — no server or install required. Paste an email body (and optionally a sender address) and click "Analyse email."
