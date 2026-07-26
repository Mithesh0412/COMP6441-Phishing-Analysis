"""
Phishing Email Analysis: Human-Generated vs LLM-Generated
Inputs:
  human-generated/phishing.csv   -> columns: sender,receiver,date,subject,body,urls,label
  llm-generated/phishing.csv     -> columns: text,label
Output:
  - features_human.json
  - features_llm.json
  - comparison_summary.json
  - case_study_candidates_human.json
  - case_study_candidates_llm.json
"""

import pandas as pd
import re
import json
from collections import Counter
from urllib.parse import urlparse

# Keyword Lists
URGENCY_WORDS = [
    "urgent", "immediately", "verify", "suspend", "suspended", "act now",
    "expire", "expires", "expired", "limited time", "click here",
    "restricted", "unauthorized", "unauthorised", "unusual activity",
    "final notice", "action required", "24 hours", "48 hours", "locked",
    "reactivate", "update your", "security alert", "prevent", "failure to comply"
]

AUTHORITY_WORDS = [
    "bank", "paypal", "amazon", "microsoft", "apple", "irs", "government", "ato",
    "security team", "head of security", "it department", "administrator",
    "support team", "netflix", "dhl", "fedex", "ups", "google", "customer support",
    "financial institution", "official"
]

TACTIC_CATEGORIES = {
    "account_suspension": ["suspend", "locked", "restricted", "unusual activity", "reactivate", "verify your account"],
    "credential_reset":   ["password", "reset your password", "login", "confirm your", "update your", "verify your account details"],
    "financial_invoice":  ["invoice", "payment", "refund", "billing", "transaction", "wire transfer", "funds"],
    "prize_reward":       ["winner", "congratulations", "claim your", "prize", "free gift", "selected", "opportunity", "compensation package"],
    "authority_impersonation": ["irs", "government", "bank", "paypal", "microsoft", "apple", "security team", "head of security", "financial institution", "ato"],
    "job_recruitment":   ["recruiter", "work-from-home", "job portal", "onboarding", "compensation package", "esteemed team"],
}

COMMON_BRANDS = ["paypal", "amazon", "microsoft", "apple", "google", "bankofamerica", "chase", "netflix", "dhl", "fedex", "ups", "irs"]

# Regex to verify URL presence in emails
URL_REGEX = re.compile(r'(?:https?://)?(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?(?:/[^\s,]*)?')
HTML_TAG_REGEX = re.compile(r'<[^>]+>')


# Helper fucntions
def strip_html(text):
    return HTML_TAG_REGEX.sub(' ', str(text))


def extract_urls(text):
    return URL_REGEX.findall(str(text))


def domain_of(url):
    try:
        if not url.startswith("http"):
            url = "http://" + url
        return urlparse(url).netloc.lower()
    except Exception:
        return url.lower()


def is_ip_based(domain):
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

# Levenshtein distance between two strings
# Code adapted from https://www.digitalocean.com/community/tutorials/levenshtein-distance-python
def levenshtein_dist(a, b):
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1])
    return dp[m][n]


# Fuzzy brand-impersonation check using levenshtein distance
# Helps catch things like 'micrasoft' that a plain substring check on 'microsoft' would miss
def find_typosquat(domain):
    d = domain.lower().lstrip("www.")
    tokens = [t for t in re.split(r'[.\-]', d) if len(t) > 3]
    for token in tokens:
        for brand in COMMON_BRANDS:
            if token == brand:
                continue
            dist = levenshtein_dist(token, brand)
            if 0 < dist <= 2 and abs(len(token) - len(brand)) <= 2:
                return {"token": token, "brand": brand, "distance": dist}
    return None


def is_lookalike_domain(domain):
    d = domain.lower()
    exact_substring = any(b in d and not d.endswith(f"{b}.com") and not d.startswith(f"{b}.") for b in COMMON_BRANDS)
    return exact_substring or find_typosquat(d) is not None


def extract_sender_domain(sender):
    m = re.search(r'@([a-zA-Z0-9.\-]+)', str(sender))
    return m.group(1) if m else ""


def count_keywords(text, wordlist):
    return [w for w in wordlist if w in text]


def is_generic_greeting(text):
    generic_patterns = ["dear customer", "dear user", "dear valued", "dear member",
                         "dear sir/madam", "to whom it may concern", "dear account holder"]
    return any(p in text[:400] for p in generic_patterns)


def is_personalized_greeting(raw_text):
    m = re.match(r'\s*dear\s+([a-z]+)', raw_text.lower())
    if not m:
        return False
    generic = ["customer", "user", "valued", "account", "sir", "madam", "team"]
    return m.group(1) not in generic


def score_tactic_categories(text):
    return [cat for cat, kws in TACTIC_CATEGORIES.items() if any(kw in text for kw in kws)]


def word_count(text):
    return len(str(text).split())


def avg_sentence_length(text):
    sentences = re.split(r'[.!?]+', str(text))
    sentences = [s for s in sentences if s.strip()]
    if not sentences:
        return 0
    return round(sum(len(s.split()) for s in sentences) / len(sentences), 1)


# Calculates a deception score based on technical and psychological indicators
# deception_score = urgency cues + authority cues + (2 * tactic breadth) + (3 if spoofing else 0)
#   - tactic categories weighted x2, since matching one requires multiple
#     related keywords to co-occur, a stronger signal than one keyword alone
#   - spoofing is a flat +3 bonus since it's binary (present/absent) rather
#     than a count, and is treated as a strong standalone red flag
def extract_features(raw_text, sender=""):
    raw_text = "" if pd.isna(raw_text) else str(raw_text)
    text_clean = strip_html(raw_text).lower()

    urls = extract_urls(raw_text)
    domains = [domain_of(u) for u in urls]

    urgency_hits = count_keywords(text_clean, URGENCY_WORDS)
    authority_hits = count_keywords(text_clean, AUTHORITY_WORDS)
    tactics = score_tactic_categories(text_clean)

    lookalike_domains = [d for d in domains if is_lookalike_domain(d)]

    sender_domain = extract_sender_domain(sender) if sender else ""
    sender_typosquat = find_typosquat(sender_domain) if sender_domain else None

    spoofing_signals = []
    if lookalike_domains:
        spoofing_signals.append(f"lookalike_url_domain:{lookalike_domains[0]}")
    if sender_typosquat:
        spoofing_signals.append(
            f"sender_typosquat:{sender_typosquat['token']}~{sender_typosquat['brand']}"
        )

    return {
        "sender": sender,
        "body_preview": strip_html(raw_text)[:600].strip(),
        "word_count": word_count(raw_text),
        "avg_sentence_length": avg_sentence_length(raw_text),
        "num_urls": len(urls),
        "domains": domains,
        "ip_based_urls": [d for d in domains if is_ip_based(d)],
        "lookalike_domains": lookalike_domains,
        "sender_typosquat": sender_typosquat,
        "spoofing_signals": spoofing_signals,
        "urgency_keywords": urgency_hits,
        "authority_keywords": authority_hits,
        "generic_greeting": is_generic_greeting(text_clean),
        "personalized_greeting": is_personalized_greeting(raw_text),
        "tactic_categories": tactics,
        "deception_score": (
            len(urgency_hits) + len(authority_hits) + 2*len(tactics)
            + (3 if spoofing_signals else 0)
        ),
    }


def summarise(features_list, label):
    n = len(features_list)
    if n == 0:
        return {"label": label, "sample_size": 0}

    tactic_counter = Counter(t for f in features_list for t in f["tactic_categories"])

    return {
        "label": label,
        "sample_size": n,
        "avg_word_count": round(sum(f["word_count"] for f in features_list) / n, 1),
        "avg_sentence_length": round(sum(f["avg_sentence_length"] for f in features_list) / n, 1),
        "pct_with_urls": round(sum(1 for f in features_list if f["num_urls"] > 0) / n * 100, 1),
        "pct_ip_based_urls": round(sum(1 for f in features_list if f["ip_based_urls"]) / n * 100, 1),
        "pct_lookalike_domains": round(sum(1 for f in features_list if f["lookalike_domains"]) / n * 100, 1),
        "pct_spoofing_signals": round(sum(1 for f in features_list if f["spoofing_signals"]) / n * 100, 1),
        "pct_urgency_language": round(sum(1 for f in features_list if f["urgency_keywords"]) / n * 100, 1),
        "pct_authority_claim": round(sum(1 for f in features_list if f["authority_keywords"]) / n * 100, 1),
        "pct_generic_greeting": round(sum(1 for f in features_list if f["generic_greeting"]) / n * 100, 1),
        "pct_personalized_greeting": round(sum(1 for f in features_list if f["personalized_greeting"]) / n * 100, 1),
        "avg_deception_score": round(sum(f["deception_score"] for f in features_list) / n, 2),
        "tactic_category_breakdown": tactic_counter.most_common(),
        "top_urgency_words": Counter(w for f in features_list for w in f["urgency_keywords"]).most_common(10),
        "top_authority_words": Counter(w for f in features_list for w in f["authority_keywords"]).most_common(10),
    }


def load_human(csv_path, sample_size):
    df = pd.read_csv(csv_path)
    df = df.sample(n=min(sample_size, len(df)), random_state=42)
    return [extract_features(row.get("body", ""), str(row.get("sender", ""))) for _, row in df.iterrows()]


def load_llm(csv_path, sample_size):
    rows = []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    for line in lines[1:]:
        line = line.rstrip("\n").rstrip("\r")
        if not line.strip():
            continue
        if "," not in line:
            continue
        text, label = line.rsplit(",", 1)
        text = text.strip()
        label = label.strip()
        if text:
            rows.append({"text": text, "label": label})

    df = pd.DataFrame(rows)
    print(f"Loaded {len(df)} rows from {csv_path}")
    df = df.sample(n=min(sample_size, len(df)), random_state=42)
    return [extract_features(row.get("text", "")) for _, row in df.iterrows()]


# Main function - calls the helpers to perform analysis and write the results to json files
def main(human_csv, llm_csv, sample_size=400):
    features_human = load_human(human_csv, sample_size)
    features_llm = load_llm(llm_csv, sample_size)

    with open("features_human.json", "w") as f:
        json.dump(features_human, f, indent=2)
    with open("features_llm.json", "w") as f:
        json.dump(features_llm, f, indent=2)

    comparison = {
        "human_generated": summarise(features_human, "human_generated_phishing"),
        "llm_generated": summarise(features_llm, "llm_generated_phishing"),
    }
    with open("comparison_summary.json", "w") as f:
        json.dump(comparison, f, indent=2)

    case_studies_human = sorted(features_human, key=lambda f: f["deception_score"], reverse=True)[:5]
    case_studies_llm = sorted(features_llm, key=lambda f: f["deception_score"], reverse=True)[:5]
    with open("case_study_candidates_human.json", "w") as f:
        json.dump(case_studies_human, f, indent=2)
    with open("case_study_candidates_llm.json", "w") as f:
        json.dump(case_studies_llm, f, indent=2)

    print(json.dumps(comparison, indent=2))


if __name__ == "__main__":
    main("human-generated/phishing.csv", "llm-generated/phishing.csv", sample_size=400)
