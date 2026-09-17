import { useState, useMemo } from "react";

const ALL_ISSUES = [
  // ── .env ──────────────────────────────────────────────────────────
  { id:1,  file:".env",           line:"1",     sev:"critical", cat:"Security",     title:"Live Gemini API key hardcoded",                    fix:"Delete value, rotate key at console.cloud.google.com, then run `git filter-repo --path .env --invert-paths` to purge history." },
  { id:2,  file:".env",           line:"2",     sev:"medium",   cat:"Security",     title:"DEBUG=True committed",                             fix:"Change to DEBUG=False. Render's yaml overrides it, but loading .env locally exposes full stack traces on errors." },

  // ── settings.py ───────────────────────────────────────────────────
  { id:3,  file:"settings.py",    line:"19",    sev:"medium",   cat:"Security",     title:"SECRET_KEY falls back to known insecure string",   fix:"Replace fallback with `raise ImproperlyConfigured('SECRET_KEY not set')`. Render generates a real one via generateValue:true." },
  { id:4,  file:"settings.py",    line:"49",    sev:"medium",   cat:"Security",     title:"CORS_ALLOW_ALL_ORIGINS = True",                    fix:"Change to CORS_ALLOWED_ORIGINS = ['https://your-app.onrender.com'] once deployed." },
  { id:5,  file:"settings.py",    line:"128",   sev:"medium",   cat:"Dead code",    title:"SECURE_BROWSER_XSS_FILTER deprecated since Django 4.0", fix:"Delete the line. It has no effect and triggers a system check warning." },
  { id:6,  file:"settings.py",    line:"—",     sev:"medium",   cat:"Security",     title:"Missing SECURE_PROXY_SSL_HEADER for Render",       fix:"Add `SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')`. Without it request.is_secure() always returns False behind Render's proxy." },
  { id:7,  file:"settings.py",    line:"27–28", sev:"medium",   cat:"Bloat",        title:"django.contrib.auth + contenttypes not needed",    fix:"Remove both from INSTALLED_APPS. No models, no admin, no auth — these only add in-memory migration overhead on every cold start." },
  { id:8,  file:"settings.py",    line:"—",     sev:"low",      cat:"Security",     title:"No Content-Security-Policy header",                fix:"Add SECURE_REFERRER_POLICY and a CSP via middleware or WhiteNoise headers config. Especially important since extracted URL content is displayed in the UI." },

  // ── requirements.txt ─────────────────────────────────────────────
  { id:9,  file:"requirements.txt", line:"19",  sev:"medium",   cat:"Bug",          title:"openai-whisper commented out",                     fix:"Uncomment it. It's installed in render.yaml's buildCommand but not here, so `pip install -r requirements.txt` locally silently breaks audio analysis." },
  { id:10, file:"requirements.txt", line:"14",  sev:"medium",   cat:"Reliability",  title:"google-genai has no version pin",                  fix:"Add `google-genai>=1.0`. Breaking API changes have already happened once in this library." },
  { id:11, file:"requirements.txt", line:"15",  sev:"medium",   cat:"Reliability",  title:"google-adk has no version pin",                    fix:"Add `google-adk>=0.5`." },
  { id:12, file:"requirements.txt", line:"7",   sev:"low",      cat:"Reliability",  title:"django has no version ceiling",                    fix:"Change to `django>=4.2,<6` to prevent unexpected major-version upgrades in CI." },
  { id:13, file:"requirements.txt", line:"9–11",sev:"low",      cat:"Reliability",  title:"drf / cors-headers / whitenoise have no version floors", fix:"Add `djangorestframework>=3.15`, `django-cors-headers>=4.3`, `whitenoise>=6.7`." },

  // ── render.yaml ──────────────────────────────────────────────────
  { id:14, file:"render.yaml",    line:"10",    sev:"medium",   cat:"Performance",  title:"Sync Gunicorn workers block on async pipeline",    fix:"Add `--worker-class gevent` and add gevent to requirements.txt. Each streaming request creates asyncio.new_event_loop() and blocks a whole OS thread for its duration." },
  { id:15, file:"render.yaml",    line:"15",    sev:"medium",   cat:"Security",     title:"ALLOWED_HOSTS = '*'",                              fix:"Replace with your actual Render domain once deployed: `mindshield-ai.onrender.com`." },
  { id:16, file:"render.yaml",    line:"5–8",   sev:"low",      cat:"Performance",  title:"Whisper model (~140 MB) not pre-downloaded",       fix:"Add `python -c \"import whisper; whisper.load_model('base')\"` to the build command so the model is baked in, not downloaded on first audio request." },

  // ── manage.py / wsgi.py / asgi.py / admin.py / apps.py ──────────
  { id:17, file:"manage.py + 4 others", line:"all", sev:"medium", cat:"Platform",  title:"Windows CRLF line endings in 5 files",             fix:"Add `.gitattributes` with `*.py text eol=lf` and run `git add --renormalize .`. Causes noisy diffs and can break shell scripts on Linux." },
  { id:18, file:"wsgi.py / asgi.py", line:"7", sev:"low",        cat:"Docs",       title:"Reference Django 6.0 docs — version doesn't exist", fix:"Change URL to `en/4.2` or `en/stable`. requirements.txt specifies `django>=4.2`." },

  // ── analyzer/views.py ────────────────────────────────────────────
  { id:19, file:"views.py",       line:"22",    sev:"critical",  cat:"Dead code",   title:"analyze_with_llm imported but never called",       fix:"Delete the import. The agent pipeline replaced it entirely. `llm_engine.py` should be marked legacy." },
  { id:20, file:"views.py",       line:"258–261",sev:"critical", cat:"Logic bug",   title:"generate_offline_fallback() bypasses compute_score()", fix:"The docstring says 'single authority' but offline mode hand-rolls `final_score = min(pattern_score + 15, 85)`. Replace with `compute_score(llm_score=0, pattern_score=..., confidence=30)`." },
  { id:21, file:"views.py",       line:"34–37", sev:"medium",    cat:"Dead code",   title:"_score() wrapper defined but never called",        fix:"Delete the function. It wraps compute_score but is never used in the actual pipeline." },
  { id:22, file:"views.py",       line:"47–64", sev:"medium",    cat:"Architecture",title:"FLAG_WEIGHTS dict belongs in scoring_engine.py",   fix:"Move it next to compute_score() and import it here. Logic that controls scoring lives in views.py." },
  { id:23, file:"views.py",       line:"150–202",sev:"medium",   cat:"Dead code",   title:"build_system_flags() defined but never called",    fix:"Either wire it into the URL pipeline metadata, or delete it. It builds domain age, TLD risk, and OCR quality flags but is never invoked." },
  { id:24, file:"views.py",       line:"229–247",sev:"medium",   cat:"Duplication", title:"merge_tactics() duplicated from agents.py:230",    fix:"Create `analyzer/utils.py`, move the function there, import in both files." },
  { id:25, file:"views.py",       line:"374, 426",sev:"medium",  cat:"Style",       title:"`import time` inside function body (twice)",        fix:"Move both to the top-level imports at lines 16–19." },
  { id:26, file:"views.py",       line:"400–401",sev:"medium",   cat:"Performance", title:"asyncio.new_event_loop() per request blocks a worker thread", fix:"Add a comment documenting the limitation. Proper fix is gevent workers (see render.yaml #14) or switching to uvicorn/ASGI." },
  { id:27, file:"views.py",       line:"433",   sev:"medium",    cat:"Validation",  title:"No minimum text length check",                     fix:"Add: `if len(content) < 10: return error('Too short for analysis.')` before calling stream_pipeline." },
  { id:28, file:"views.py",       line:"467",   sev:"medium",    cat:"Validation",  title:"No maximum text length limit",                     fix:"Add: `if len(content) > 8000: return error('Exceeds 8,000 character limit.')`. Unbounded input sends unlimited tokens to Gemini." },

  // ── analyzer/agents.py ───────────────────────────────────────────
  { id:29, file:"agents.py",      line:"254, 402",sev:"critical",cat:"Bug",         title:"All concurrent users share user_id='default_user'", fix:"Pass `user_id=str(uuid.uuid4())` from views.py when calling run_multi_agent_pipeline. Shared ID causes ADK session contamination between concurrent requests." },
  { id:30, file:"agents.py",      line:"150",   sev:"critical",  cat:"Bug",         title:"agent.model = CURRENT_MODEL mutates shared module-level objects", fix:"Use `local_agent = copy.copy(agent); local_agent.model = current_model` inside run_single_agent. The four agent objects are singletons — mutating them causes concurrent requests to interfere." },
  { id:31, file:"agents.py",      line:"16",    sev:"medium",    cat:"Dead code",   title:"GEMINI_API_KEY loaded but never used",             fix:"Delete lines 16–17. Google ADK reads the env var directly via its own mechanism." },
  { id:32, file:"agents.py",      line:"87",    sev:"medium",    cat:"Bug",         title:"CURRENT_MODEL global mutated on rate-limit without any concurrency protection", fix:"At minimum add a comment. Proper fix: pass model as a parameter to run_single_agent instead of using a global." },
  { id:33, file:"agents.py",      line:"151",   sev:"medium",    cat:"Performance", title:"New InMemoryRunner + session created on every agent call", fix:"Create the runner once per pipeline run and pass it as a parameter. Currently 4–24 runner instantiations per request depending on retries." },
  { id:34, file:"agents.py",      line:"269",   sev:"medium",    cat:"Validation",  title:"No content truncation before sending to Gemini API", fix:"Add `text = text[:6000]` before building the ingestion_prompt. llm_engine.py correctly caps at 4000 chars; the agent path skips that entirely." },
  { id:35, file:"agents.py",      line:"121–176",sev:"medium",   cat:"Style",       title:"Long agent instruction strings inlined in Agent() calls", fix:"Extract to an `AGENT_PROMPTS = {'ingestion': '...', 'detection': '...'}` dict at the top of the file for readability and maintainability." },
  { id:36, file:"agents.py",      line:"230–246",sev:"medium",   cat:"Duplication", title:"merge_tactics() duplicated from views.py:229",     fix:"Same as views.py #24 — move to utils.py." },
  { id:37, file:"agents.py",      line:"318",   sev:"medium",    cat:"Style",       title:"Magic numbers 10 and 30 in flags_score calculation",fix:"Add comment: `# 10 pts per LLM-detected pattern, capped at 3 patterns (30 pts max)`." },
  { id:38, file:"agents.py",      line:"370",   sev:"medium",    cat:"Style",       title:"`from .scoring_engine import ...` inside async generator body", fix:"Move to top-level imports at lines 1–9." },
  { id:39, file:"agents.py",      line:"27–28", sev:"low",       cat:"Reliability", title:"Model names not verified against current Google API", fix:"Cross-check `gemini-2.5-flash-lite`, `gemini-2.5-flash` etc. against ai.google.dev — these names change. Also note gemini-2.0-flash in llm_engine.py is inconsistent." },
  { id:40, file:"agents.py",      line:"413–414",sev:"low",      cat:"Logic",       title:"Trusted domain gets double-discounted",            fix:"compute_score() already reduces score via low url_rule_score for trusted domains, then agents.py applies a second `final_score * 0.6` multiplier. Confirm this is intentional and add a comment." },

  // ── analyzer/scoring_engine.py ───────────────────────────────────
  { id:41, file:"scoring_engine.py",line:"39",  sev:"medium",   cat:"Bug",          title:"LEETSPEAK_MAP maps '9' → 'g' (wrong)",             fix:"Change to `'9': 'q'`. The digit 9 visually resembles q, not g. g is already mapped from 6." },
  { id:42, file:"scoring_engine.py",line:"54",  sev:"low",      cat:"Style",        title:"Variable `text_lower` misleading inside normalize function", fix:"Rename to `text_original_lower` — it's the pre-normalization baseline. `normalized` starts as a copy of it then changes, which is confusing." },
  { id:43, file:"scoring_engine.py",line:"387", sev:"low",      cat:"Style",        title:"conf_penalty formula written as -0.10 * conf_penalty * 10", fix:"conf_penalty = (100-conf)*0.10, so -0.10*conf_penalty*10 = -conf_penalty. Write directly as `-conf_penalty` to match the non-URL formula on line 396." },
  { id:44, file:"scoring_engine.py",line:"404", sev:"low",      cat:"Docs",         title:"Low-confidence regression to 25 has no explanatory comment", fix:"Add: `# Regress toward Low (25) not Safe (0) — bad OCR/audio with real patterns should still show some risk`." },

  // ── analyzer/llm_engine.py ───────────────────────────────────────
  { id:45, file:"llm_engine.py",   line:"346",  sev:"medium",   cat:"Performance",  title:"genai_new.Client() created inside retry loop on every call", fix:"Initialize once at module level: `_gemini_client = genai_new.Client(api_key=GEMINI_API_KEY)` and reuse it." },
  { id:46, file:"llm_engine.py",   line:"348",  sev:"medium",   cat:"Consistency",  title:"model='gemini-2.0-flash' inconsistent with agents.py", fix:"Align to the same model. agents.py uses gemini-2.5-flash-lite as primary; llm_engine.py uses gemini-2.0-flash. Pick one." },
  { id:47, file:"llm_engine.py",   line:"231–243",sev:"medium", cat:"Dead code",    title:"Two redundant JSON extraction regex passes",       fix:"The second regex (greedy re.DOTALL) is a strict superset of the first. Remove the first pass and keep only the greedy one." },
  { id:48, file:"llm_engine.py",   line:"36–38",sev:"low",      cat:"Docs",         title:"Ollama config present but never used in production",fix:"Add a comment block: `# OLLAMA_* vars are for local development only. Not used on Render.`" },
  { id:49, file:"llm_engine.py",   line:"50–64",sev:"low",      cat:"Docs",         title:"Cache uses FIFO eviction with no documentation",   fix:"Add comment: `# Eviction: FIFO (not LRU). First 50 keys deleted when limit of 100 is reached.`" },
  { id:50, file:"llm_engine.py",   line:"118",  sev:"low",      cat:"Correctness",  title:"sanitize_input pattern `respond\\s+with\\s+json` too broad", fix:"Narrow to `respond\\s+only\\s+with\\s+json` to avoid false-positives on legitimate content discussing JSON APIs." },

  // ── analyzer/url_engine.py ───────────────────────────────────────
  { id:51, file:"url_engine.py",   line:"202",  sev:"medium",   cat:"Reliability",  title:"URL fetch timeout hardcoded to 10 seconds",        fix:"Replace with `URL_FETCH_TIMEOUT = int(os.getenv('URL_FETCH_TIMEOUT', '10'))` so it's configurable." },
  { id:52, file:"url_engine.py",   line:"203–206",sev:"medium", cat:"Bug",          title:"No content-type check before BeautifulSoup parsing", fix:"Add: `if 'text' not in response.headers.get('Content-Type', ''): return '', ''`. PDFs and binaries currently produce garbage text." },
  { id:53, file:"url_engine.py",   line:"249–254",sev:"medium", cat:"Reliability",  title:"whois.whois() has no timeout — can hang 30–60 s",  fix:"Wrap with a thread-based timeout (concurrent.futures on Windows) or signal.alarm on Linux. Some TLD WHOIS servers are unresponsive." },
  { id:54, file:"url_engine.py",   line:"296–303",sev:"medium", cat:"Performance",  title:"detect_subdomain_spoof and detect_homoglyph_attack called twice", fix:"Both are called in extract_domain_info (lines 235, 241) and again inside url_structure_risk (lines 296–303). Pass results as arguments to avoid double computation." },

  // ── analyzer/audio_engine.py ─────────────────────────────────────
  { id:55, file:"audio_engine.py", line:"20",   sev:"medium",   cat:"Portability",  title:"Personal Windows path hardcoded (C:\\Users\\THAMARAI SELVAN\\...)", fix:"Replace with `r'C:\\ffmpeg\\bin'` and `r'C:\\Program Files\\ffmpeg\\bin'` as generic fallbacks." },
  { id:56, file:"audio_engine.py", line:"28",   sev:"medium",   cat:"Bug",          title:"os.environ.get('USERPROFILE', '') gives wrong path when unset", fix:"Use `os.path.expanduser('~')` which works on all platforms and always returns a valid path." },
  { id:57, file:"audio_engine.py", line:"43",   sev:"medium",   cat:"Performance",  title:"Whisper model loaded at module import time (~140 MB)", fix:"Lazy-load: set `_whisper_model = None` and load on first `transcribe_audio()` call. Speeds up cold starts when audio isn't used." },
  { id:58, file:"audio_engine.py", line:"64–79",sev:"low",      cat:"Docs",         title:"no_speech_prob semantics not documented",          fix:"Add comment: `# no_speech_prob: 0.0 = clear speech, 1.0 = silence/noise. Good speech typically 0.0–0.2.`" },

  // ── analyzer/ocr_engine.py ───────────────────────────────────────
  { id:59, file:"ocr_engine.py",   line:"20",   sev:"medium",   cat:"Portability",  title:"Personal Windows path hardcoded (C:\\Users\\THAMARAI SELVAN\\...)", fix:"Replace with `r'C:\\Program Files\\Tesseract-OCR\\tesseract.exe'` as the standard install fallback." },
  { id:60, file:"ocr_engine.py",   line:"138",  sev:"low",      cat:"Style",        title:"conf >= 40 is a magic number",                    fix:"Extract as `OCR_MIN_WORD_CONFIDENCE = 40` at the top of the file." },
  { id:61, file:"ocr_engine.py",   line:"152",  sev:"low",      cat:"Style",        title:"fallback_conf = 50 is a magic number",             fix:"Extract as `OCR_FALLBACK_CONFIDENCE = 50` at the top of the file." },
  { id:62, file:"ocr_engine.py",   line:"260–262",sev:"low",    cat:"Logic",        title:"Second OCR pass accepts longer result even if confidence collapses", fix:"Add confidence gate: `if len(text2) > len(text) and conf2 >= conf * 0.7:` to avoid accepting longer but much lower quality text." },

  // ── frontend/app.js ──────────────────────────────────────────────
  { id:63, file:"app.js",          line:"169",  sev:"medium",   cat:"UX",           title:"Error says 'Make sure the server is running' in production", fix:"Change to `'Connection error. Please try again.'` — users on Render can't start a server." },
  { id:64, file:"app.js",          line:"288",  sev:"medium",   cat:"Bug",          title:"|| 0 hides legitimate score of 0 (use ?? instead)",fix:"Change `d.fake_probability || 0` → `d.fake_probability ?? 0`. Same fix for emotional/deception/coercion on lines 324–326." },
  { id:65, file:"app.js",          line:"316",  sev:"medium",   cat:"Bug",          title:".replace('_',' ') only replaces first underscore",fix:"Change to `.replace(/_/g, ' ')` with a regex global flag. 'LOW_CONFIDENCE_MODE' → 'LOW CONFIDENCE MODE'." },
  { id:66, file:"app.js",          line:"401",  sev:"low",      cat:"Docs",         title:"Magic number 70 in pattern bar normalization",     fix:"Add comment: `// 70 = scoring_engine.py pattern score cap`." },
  { id:67, file:"app.js",          line:"407",  sev:"low",      cat:"Bug risk",     title:"setBar('urlBarRow', ...) passes container div ID, not bar element ID", fix:"Verify `#urlBarRow` directly contains `.bar-fill` and `.bar-value`. If it's a wrapper div, setBar will silently fail to update the bar." },
  { id:68, file:"app.js",          line:"495–500",sev:"low",    cat:"UX",           title:"animateGauge counter takes ~1 second for scores below 40", fix:"Cap duration: `const step = Math.max(1, Math.ceil(score / (600/25)))` so animation always finishes within 600 ms." },

  // ── frontend/index.html ──────────────────────────────────────────
  { id:69, file:"index.html",      line:"93",   sev:"medium",   cat:"Validation",   title:"URL input missing pattern validation",             fix:"Add `pattern='https?://.*'` to the input. type='url' alone accepts bare domains without a scheme, which your backend then rejects." },
  { id:70, file:"index.html",      line:"87",   sev:"medium",   cat:"Validation",   title:"Textarea has no maxlength attribute",              fix:"Add `maxlength='8000'` to match the backend limit added in views.py #28." },
  { id:71, file:"index.html",      line:"<head>",sev:"low",     cat:"SEO/Privacy",  title:"No <meta name='robots'> tag",                     fix:"Add `<meta name='robots' content='noindex, nofollow'>`. The tool processes sensitive content; search engine indexing is undesirable." },

  // ── frontend/style.css ───────────────────────────────────────────
  { id:72, file:"style.css",       line:"5",    sev:"medium",   cat:"Performance",  title:"Google Fonts loaded via @import (render-blocking)",fix:"Remove @import. Add preconnect + stylesheet <link> tags to index.html <head> instead. @import in CSS blocks all page rendering until the font loads." },
  { id:73, file:"style.css",       line:"407",  sev:"low",      cat:"UX",           title:"extracted-text max-height: 120px is too cramped",  fix:"Increase to `max-height: 300px` or add a 'Show full text' toggle. Long URL extractions show only ~4 lines." },

  // ── Missing infrastructure ───────────────────────────────────────
  { id:74, file:"(missing)",       line:"—",    sev:"critical",  cat:"Quality",     title:"Zero test coverage across the entire project",     fix:"Start with `tests/test_scoring.py` — compute_score and detect_scam_patterns are pure functions, perfect for unit tests. Even 5 tests would catch regressions." },
  { id:75, file:"(missing)",       line:"—",    sev:"medium",    cat:"Platform",    title:"No .gitattributes file for line ending enforcement", fix:"Create `.gitattributes` with `*.py text eol=lf` and `*.js text eol=lf`. Prevents CRLF from re-entering on Windows contributors." },
];

const SEV_ORDER = { critical:0, medium:1, low:2 };
const SEV_META = {
  critical: { label:"Critical", color:"#ef4444", bg:"#fef2f2", dot:"#dc2626" },
  medium:   { label:"Medium",   color:"#d97706", bg:"#fffbeb", dot:"#b45309" },
  low:      { label:"Low",      color:"#3b82f6", bg:"#eff6ff", dot:"#2563eb" },
};

const UNIQUE_FILES  = ["(all)", ...Array.from(new Set(ALL_ISSUES.map(i => i.file))).sort()];
const UNIQUE_CATS   = ["(all)", ...Array.from(new Set(ALL_ISSUES.map(i => i.cat))).sort()];
const UNIQUE_SEVS   = ["(all)", "critical", "medium", "low"];

export default function App() {
  const [sevFilter,  setSevFilter]  = useState("(all)");
  const [fileFilter, setFileFilter] = useState("(all)");
  const [catFilter,  setCatFilter]  = useState("(all)");
  const [search,     setSearch]     = useState("");
  const [expanded,   setExpanded]   = useState(null);

  const filtered = useMemo(() => {
    return ALL_ISSUES
      .filter(i => sevFilter  === "(all)" || i.sev  === sevFilter)
      .filter(i => fileFilter === "(all)" || i.file === fileFilter)
      .filter(i => catFilter  === "(all)" || i.cat  === catFilter)
      .filter(i => {
        if (!search) return true;
        const q = search.toLowerCase();
        return i.title.toLowerCase().includes(q) || i.fix.toLowerCase().includes(q) || i.file.toLowerCase().includes(q);
      })
      .sort((a,b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || a.id - b.id);
  }, [sevFilter, fileFilter, catFilter, search]);

  const counts = useMemo(() => ({
    critical: ALL_ISSUES.filter(i => i.sev === "critical").length,
    medium:   ALL_ISSUES.filter(i => i.sev === "medium").length,
    low:      ALL_ISSUES.filter(i => i.sev === "low").length,
  }), []);

  return (
    <div style={{ fontFamily:"system-ui,-apple-system,sans-serif", maxWidth:860, margin:"0 auto", padding:"20px 16px", color:"#111" }}>
      {/* Header */}
      <div style={{ marginBottom:20 }}>
        <div style={{ fontSize:13, color:"#6b7280", marginBottom:4, fontWeight:500, letterSpacing:"0.05em", textTransform:"uppercase" }}>MindShield AI · Complete Code Review</div>
        <h1 style={{ fontSize:22, fontWeight:700, margin:"0 0 12px" }}>All Issues — {ALL_ISSUES.length} total</h1>
        <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
          {["critical","medium","low"].map(s => (
            <div key={s} onClick={() => setSevFilter(sevFilter === s ? "(all)" : s)}
              style={{ display:"flex", alignItems:"center", gap:6, padding:"5px 12px", borderRadius:20,
                background: sevFilter===s ? SEV_META[s].bg : "#f3f4f6",
                border:`1px solid ${sevFilter===s ? SEV_META[s].color : "#e5e7eb"}`,
                cursor:"pointer", userSelect:"none", transition:"all .15s" }}>
              <span style={{ width:8, height:8, borderRadius:"50%", background:SEV_META[s].dot, flexShrink:0 }}/>
              <span style={{ fontSize:13, fontWeight:600, color:sevFilter===s ? SEV_META[s].color : "#374151" }}>
                {SEV_META[s].label}
              </span>
              <span style={{ fontSize:12, color:"#9ca3af", fontWeight:500 }}>{counts[s]}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Filters */}
      <div style={{ display:"flex", gap:8, marginBottom:14, flexWrap:"wrap" }}>
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search issues…"
          style={{ flex:1, minWidth:160, padding:"7px 12px", border:"1px solid #e5e7eb", borderRadius:8,
            fontSize:13, outline:"none", background:"#fafafa" }}/>
        <select value={fileFilter} onChange={e => setFileFilter(e.target.value)}
          style={{ padding:"7px 10px", border:"1px solid #e5e7eb", borderRadius:8, fontSize:12, background:"#fafafa", cursor:"pointer" }}>
          {UNIQUE_FILES.map(f => <option key={f} value={f}>{f === "(all)" ? "All files" : f}</option>)}
        </select>
        <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
          style={{ padding:"7px 10px", border:"1px solid #e5e7eb", borderRadius:8, fontSize:12, background:"#fafafa", cursor:"pointer" }}>
          {UNIQUE_CATS.map(c => <option key={c} value={c}>{c === "(all)" ? "All categories" : c}</option>)}
        </select>
      </div>

      {/* Count */}
      <div style={{ fontSize:12, color:"#9ca3af", marginBottom:10 }}>
        Showing {filtered.length} of {ALL_ISSUES.length} issues
        {(sevFilter!=="(all)"||fileFilter!=="(all)"||catFilter!=="(all)"||search) &&
          <button onClick={() => { setSevFilter("(all)"); setFileFilter("(all)"); setCatFilter("(all)"); setSearch(""); }}
            style={{ marginLeft:10, fontSize:12, color:"#6b7280", background:"none", border:"none", cursor:"pointer", textDecoration:"underline" }}>
            Clear filters
          </button>}
      </div>

      {/* Issue list */}
      <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
        {filtered.map(issue => {
          const m = SEV_META[issue.sev];
          const open = expanded === issue.id;
          return (
            <div key={issue.id}
              onClick={() => setExpanded(open ? null : issue.id)}
              style={{ border:`1px solid ${open ? m.color : "#e5e7eb"}`, borderLeft:`3px solid ${m.dot}`,
                borderRadius:8, background:open ? m.bg : "#fff",
                cursor:"pointer", transition:"all .15s", overflow:"hidden" }}>
              <div style={{ display:"flex", alignItems:"flex-start", gap:10, padding:"10px 14px" }}>
                {/* Sev dot */}
                <span style={{ width:8, height:8, borderRadius:"50%", background:m.dot, flexShrink:0, marginTop:5 }}/>
                {/* Number */}
                <span style={{ fontSize:11, color:"#9ca3af", fontWeight:600, minWidth:22, marginTop:1, flexShrink:0 }}>
                  #{issue.id}
                </span>
                {/* Main */}
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
                    <span style={{ fontSize:13, fontWeight:600, color:"#111" }}>{issue.title}</span>
                    <span style={{ fontSize:11, padding:"1px 7px", borderRadius:10,
                      background:m.bg, color:m.color, border:`1px solid ${m.color}30`, fontWeight:600, whiteSpace:"nowrap" }}>
                      {m.label}
                    </span>
                  </div>
                  <div style={{ display:"flex", gap:12, marginTop:3, flexWrap:"wrap" }}>
                    <span style={{ fontSize:11, color:"#6b7280" }}>
                      <span style={{ fontFamily:"monospace", background:"#f3f4f6", padding:"1px 5px", borderRadius:3 }}>{issue.file}</span>
                    </span>
                    {issue.line !== "—" && (
                      <span style={{ fontSize:11, color:"#6b7280" }}>line {issue.line}</span>
                    )}
                    <span style={{ fontSize:11, color:"#6b7280",
                      background:"#f0fdf4", border:"1px solid #bbf7d0", padding:"0px 6px", borderRadius:10, color:"#166534" }}>
                      {issue.cat}
                    </span>
                  </div>
                </div>
                {/* Chevron */}
                <span style={{ fontSize:14, color:"#9ca3af", flexShrink:0, marginTop:1, transition:"transform .2s",
                  transform: open ? "rotate(180deg)" : "rotate(0deg)", display:"inline-block" }}>▾</span>
              </div>
              {open && (
                <div style={{ padding:"0 14px 14px 44px", borderTop:`1px solid ${m.color}20` }}>
                  <div style={{ fontSize:13, color:"#374151", lineHeight:1.6 }}>
                    <strong style={{ color:"#111" }}>Fix: </strong>{issue.fix}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div style={{ textAlign:"center", padding:"40px 20px", color:"#9ca3af", fontSize:14 }}>
          No issues match your filters.
        </div>
      )}

      {/* Footer */}
      <div style={{ marginTop:24, padding:"12px 16px", background:"#f9fafb", border:"1px solid #e5e7eb",
        borderRadius:8, fontSize:12, color:"#6b7280", display:"flex", justifyContent:"space-between", flexWrap:"wrap", gap:8 }}>
        <span>{counts.critical} critical · {counts.medium} medium · {counts.low} low · {ALL_ISSUES.length} total</span>
        <span>Click any issue to expand the fix</span>
      </div>
    </div>
  );
}
