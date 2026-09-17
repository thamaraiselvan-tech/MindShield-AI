# 🛡️ MindShield AI

**Detecting Psychological Manipulation in Digital Media**

MindShield AI is a privacy-first, multimodal AI system that detects psychological manipulation tactics, scams, and misinformation in text, URLs, images, and audio. It explains *why* content is flagged in plain, everyday language that anyone can understand.

---

## ✨ Key Features

- **Multi-Agent Orchestration** — Powered by **Google ADK** (Agent Development Kit) & Gemini 2.5 Flash Lite, using a team of 4 specialized collaborative agents:
  1. *Ingestion Agent*: Cleans, structures, and extracts metadata.
  2. *Pattern Detection Agent*: Scans content for psychological manipulation tactics.
  3. *Risk Scoring Agent*: Estimates multi-dimensional threat scores (Emotional, Deception, Coercion).
  4. *Explanation & Shield Agent*: Translates complex risk analysis into layperson terms.
- **Bilingual Output (English + Tamil)** — Automatic high-fidelity explanations and shield guidelines produced natively in both English and Tamil.
- **3D Risk Score Dimensions Dashboard** — Detailed visual dashboard showing breakdown of threat across Emotional, Deceptive, and Coercive dimensions.
- **Live Agent Status Timeline** — Real-time progression pipeline status (Ingesting -> Detecting -> Scoring -> Shielding -> Complete) streamed directly using `StreamingHttpResponse`.
- **Multimodal Analysis** — Text, URLs, images (OCR), and audio (Whisper transcription).
- **10 Manipulation Tactics** — Fear, Urgency, Authority, Social Proof, Emotional Exploitation, Gaslighting, Scarcity, Reciprocity, Information Manipulation, Identity Deception.
- **55+ Pattern Rules** — Regex-based detection engine works in tandem with the Multi-Agent AI system.
- **Adaptive Scoring** — Unified scoring authority (`compute_score`) adjusting weights based on input quality.
- **Zero-Storage Privacy** — In-memory database only. Content is processed once and immediately discarded.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Tesseract OCR (for image analysis)
- FFmpeg (for audio analysis, optional)

### Installation

```bash
git clone https://github.com/thamaraiselvan-tech/MindShield-AI.git
cd MindShield-AI

pip install -r requirements.txt

# Optional: for audio analysis
pip install openai-whisper
```

### Set your API key

```bash
# Windows
set GEMINI_API_KEY=your_api_key_here

# Linux/Mac
export GEMINI_API_KEY=your_api_key_here
```

Get a free Gemini API key at: https://aistudio.google.com/apikey

### Run

```bash
python manage.py runserver
```

Open http://127.0.0.1:8000 in your browser.

---

## 📊 How Scoring Works

### Text / Image / Audio
```
final = w_llm × LLM_score + w_flags × flags_score + w_patterns × pattern_score + confidence_penalty
```
Weights adapt based on input confidence:
| Confidence | LLM Weight | Flags Weight | Patterns Weight |
|---|---|---|---|
| ≥ 75% | 55% | 25% | 20% |
| 50-74% | 45% | 30% | 25% |
| 30-49% | 30% | 35% | 35% |
| < 30% | 20% | 40% | 40% |

### URL
```
final = 0.50 × LLM + 0.20 × URL_rules + 0.20 × patterns + 0.10 × conf_penalty
```

### Risk Levels
| Score | Level |
|---|---|
| 0-14 | Safe |
| 15-34 | Low |
| 35-59 | Medium |
| 60-79 | High |
| 80-100 | Critical |

---

## 🔒 Privacy

- **In-memory database** — Nothing persisted to disk
- **No admin panel** — No user accounts or stored data
- **No sessions** — Stateless API
- **No logging of content** — User input is never written to logs
- **Process-and-discard** — Content is analyzed in memory and immediately freed

---

## 🏗️ Architecture

```
MindShield AI/
├── frontend/
│   ├── index.html          # SPA frontend with live timeline and 3D metrics
│   ├── style.css           # Cyberpunk dark theme with timeline animations
│   └── app.js              # Streaming fetch reader & UI manager
├── analyzer/
│   ├── agents.py           # Multi-agent team definitions & ADK Runner
│   ├── llm_engine.py       # Gemini API client wrapper
│   ├── scoring_engine.py   # Unified compute_score & 55 regex patterns
│   ├── ocr_engine.py       # Tesseract OCR pipeline
│   ├── url_engine.py       # URL/domain analysis
│   ├── audio_engine.py     # Whisper transcription
│   └── views.py            # API endpoints with StreamingHttpResponse JSON lines
├── MindShieldAI/
│   ├── settings.py         # Django settings
│   └── urls.py             # Route mappings
├── requirements.txt
├── render.yaml
└── README.md
```

### Multi-Agent Pipeline Flow
1. **Ingest**: Raw text is normalized, language and sender context are extracted.
2. **Detect**: Specific tactics (e.g., Gaslighting, Urgency) are mapped to quotes.
3. **Score**: Individual severity levels (0-100) are generated across 3 distinct dimensions.
4. **Shield**: Natural language summaries and defensive tips are generated in English and Tamil.
5. **Finalize**: Single scoring authority (`compute_score`) merges agent insights with structural indicators (e.g. invalid SSL, lookup spoofing, character homoglyphs) to output the final risk verdict.

---

## 🌐 Deployment (Render)

1. Push to GitHub
2. Connect repo on [Render](https://render.com)
3. Set environment variable: `GEMINI_API_KEY`
4. Deploy — `render.yaml` handles everything automatically

---

## 📝 API

### `POST /analyze/`

**Text:**
```bash
curl -X POST http://localhost:8000/analyze/ -d "text=Your suspicious message here"
```

**URL:**
```bash
curl -X POST http://localhost:8000/analyze/ -d "url=https://suspicious-site.xyz"
```

**Image:**
```bash
curl -X POST http://localhost:8000/analyze/ -F "image=@screenshot.png"
```

**Audio:**
```bash
curl -X POST http://localhost:8000/analyze/ -F "audio=@recording.mp3"
```

### Response includes:
- `fake_probability` — 0-100 risk score
- `risk_level` — Safe / Low / Medium / High / Critical
- `manipulation_tactics` — Array of detected tactics with evidence
- `plain_english_explanation` — Simple explanation anyone can understand
- `recommendation` — Actionable advice
- `score_breakdown` — Full transparency of how the score was calculated

---

## 📄 License

MIT License