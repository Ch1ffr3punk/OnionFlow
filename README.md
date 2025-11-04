# OnionFlow (OFC & OFA)

A user-friendly toolset for monitoring and analyzing **Tor network traffic** designed for **non-technical users** who care about privacy and anonymity.  
No hex dumps. No jargon. Just clear insights into your Tor usage.

---

## Overview

This toolkit helps you understand how you interact with the Tor network by capturing and analyzing your own traffic in real time. It groups raw packets into meaningful **activity streams**, assesses **anonymity risk**, and provides easy-to-read reports—all without exposing technical details.

Perfect for:
- Journalists verifying anonymity
- Privacy-conscious users
- Researchers studying Tor behavior
- Educators demonstrating network privacy

---

## Tools Included

### 1. **OnionFlow Capture** (`ofc.go`)
Captures live Tor traffic and filters out technical noise.

**Key Features:**
- Monitors ports `443` and `9001`
- Uses the [Onionoo API](https://metrics.torproject.org/onionoo.html) to identify Tor relays
- Groups packets into human-readable **streams**
- Provides real-time **risk assessment**
- Uses Unix timestamps for precision

**Output Files (saved in current directory):**
- `tor_capture_[TIMESTAMP].txt` – Filtered packet data  
- `tor_analysis_[TIMESTAMP].txt` – Session analysis  
- `tor_streams_[TIMESTAMP].txt` – Stream correlations  
- `tor_payloads_[TIMESTAMP].txt` – Behavioral patterns  
- `tor_relays_[TIMESTAMP].txt` – Identified Tor relay IPs  

---

### 2. **OnionFlow Analyzer** (`ofa.go`)
Analyzes multiple capture sessions and correlates activity over time.

**Key Features:**
- Links packets into coherent streams
- Detects upload/download patterns
- Calculates anonymity **risk scores**
- Generates 6 types of reports

**Output Reports (saved to reports folder in current directory):**
- `tor_session_table_[TIMESTAMP].txt` – Session overview  
- `tor_analysis_report_[TIMESTAMP].txt` – Detailed technical analysis  
- `tor_behavioral_analysis_[TIMESTAMP].txt` – Pattern trends  
- `tor_detailed_stream_analysis_[TIMESTAMP].txt` – In-depth stream data  
- `tor_simple_summary_[TIMESTAMP].txt` – **Beginner-friendly summary**  
- `tor_stream_correlation_[TIMESTAMP].txt` – Clear activity timeline   

---

## How It Works (For Beginners)

Instead of showing raw packets, the tools present **streams** like this:

STREAM 5: UPLOAD ACTIVITY
Total Packets: 12 | Total Data: 5840 bytes | Duration: 5 seconds
Time: 14:29:27 to 14:29:32

This stream contains the following packet sequence:
Frames: 101 to 112 (12 packets in sequence)
Likely represents: Medium data upload or form data


**What this means:**
- You sent **5.8 KB** of data (e.g., a form or file)
- It took **5 seconds**
- All 12 packets belong to the **same action**

---

## Risk Assessment

Your traffic is scored for anonymity risk:

| Risk Level | Score Range | Meaning |
|-----------|-------------|--------|
| **LOW**   | 0–30%       | Normal browsing, strong anonymity |
| **MEDIUM**| 31–50%      | Some identifiable patterns |
| **HIGH**  | 51–100%     | Clear behavioral fingerprints — consider changing habits |

**Tip:** Focus on `tor_simple_summary.txt` and `tor_stream_correlation.txt` for quick insights.

---

## Usage Guide

### Step 1: Capture Traffic
1. Run `ofc.exe` **as Administrator** (Windows only)
2. Enter number of packets to capture (default: `1000`)
3. Use **Tor Browser** (or any Tor app) normally during capture
4. Results are saved to your **current directory**

### Step 2: Analyze Patterns
1. Run `ofa.exe` anytime
2. It auto-detects all capture files
3. Generates 6 reports in folder **reports** to your current directory  

---

## Privacy & Safety

- **Local-only analysis** — no data leaves your machine  
- **No hex dumps** or raw packet displays  
- **No network manipulation** — only passive observation  
- Designed for **educational and privacy purposes**

---

## Requirements

- **Windows OS** (Administrator privileges required for capture)
- [Wireshark](https://www.wireshark.org/) installed (for packet capture backend)
- **Tor Browser** or another Tor-enabled application (to generate meaningful traffic)

---

## Key Terms

| Term | Meaning |
|------|--------|
| **Stream** | A group of packets representing one user action (e.g., loading a page) |
| **Frame** | A single network packet |
| **Upload** | Data you **send** (e.g., form submission) |
| **Download** | Data you **receive** (e.g., webpage content) |
| **Unix Timestamp** | Precise time in seconds since Jan 1, 1970 |
| **Risk Score** | How uniquely identifiable your usage pattern is |

---

**Remember:** This tool analyzes **only your own traffic**. Use it to learn, protect your privacy, and stay safe on Tor.

---

## Support the Project

If you find this toolkit helpful, consider a small donation in crypto currencies:

- **Bitcoin (BTC):** `bc1qhgek8p5qcwz7r6502y8tvenkpsw9w5yafhatxk`
- **Nym:** `n1yql04xjhmlhfkjsk8x8g7fynm27xzvnk23wfys`  
- **Monero (XMR):** `45TJx8ZHngM4GuNfYxRw7R7vRyFgfMVp862JqycMrPmyfTfJAYcQGEzT27wL1z5RG1b5XfRPJk97KeZr1svK8qES2z1uZrS`  

Or if you prefer  

<a href="https://www.buymeacoffee.com/Ch1ffr3punk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="41" width="174"></a>

















