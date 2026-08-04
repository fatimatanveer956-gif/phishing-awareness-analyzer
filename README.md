# Aegis — Phishing Awareness Analysis

**DecodeLabs Cybersecurity Internship — Defensive Logic Track, Project 3**

A tool that analyzes emails and messages to identify phishing attempts, built as both a Python CLI script and a premium web dashboard ("Aegis").

## Goal

Analyze sample emails or messages to identify phishing attempts.

## Key Requirements

* Identify suspicious links or keywords
* List red flags found in phishing messages
* Explain why the message is unsafe

## What's in this repo

|File|Description|
|-|-|
|`phishing\_analyzer.py`|Python CLI implementation — analyze built-in samples or your own pasted message|
|`index.html`|Interactive web dashboard — live risk scoring, inline highlighted red flags, threat cards, and recommendations|

## Running the Python version

```bash
python3 phishing\_analyzer.py
```

Choose a built-in sample or paste your own message. The script lists every red flag it finds and gives a LOW / MEDIUM / HIGH risk verdict with an explanation.

## Running the web version

Open `index.html` in a browser — no installation or internet connection needed (all detection runs locally in JavaScript).

## How it works

The analyzer checks a message against three categories of phishing indicators:

* **Suspicious links** — raw IP addresses instead of domains, URL shorteners that hide the real destination, high-risk domain endings, and hyphen-heavy spoofed-looking URLs
* **Urgency / pressure language** — phrases like "act now," "your account will be suspended," "click here"
* **Sensitive info requests** — asks for passwords, card numbers, SSNs, or gift cards
* **Generic greetings** — "Dear Customer" instead of your actual name, a sign of a mass-sent message

Each match found increases a weighted risk score (0–100), which maps to a LOW / MEDIUM / HIGH RISK verdict along with a plain-English explanation of what to do next.

## Example

A message containing a generic greeting, urgency language, and a raw-IP link scores as **HIGH RISK** — because it's not one suspicious detail, it's a whole pattern of manipulation tactics stacked together, which is how real phishing emails are built.

## Skills demonstrated

Threat analysis · awareness of cyber attacks · security thinking · Python · pattern/keyword detection · HTML/CSS/JS dashboard design

\---

Part of the DecodeLabs Cybersecurity Internship series. See Project 1 (Password Strength Checker) and Project 2 (Caesar Cipher) for earlier projects in this track.

