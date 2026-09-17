/* ================================================
   MindShield AI — Frontend Logic
   ================================================ */
(function () {
  "use strict";

  const API = "/analyze/";
  let currentTab = "text";
  let selectedFile = null;

  /* ── DOM References ── */
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  const tabBtns = $$(".tab-btn");
  const inputAreas = $$(".input-area");
  const analyzeBtn = $("#analyzeBtn");
  const resultsEl = $("#results");
  const errorToast = $("#errorToast");

  /* ================================================
     TAB SWITCHING
     ================================================ */
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      currentTab = btn.dataset.type;
      tabBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      inputAreas.forEach((a) => {
        a.classList.toggle("active", a.dataset.type === currentTab);
      });
      hideError();
      selectedFile = null;
      $$(".file-name").forEach((f) => (f.style.display = "none"));
    });
  });

  /* ================================================
     FILE DRAG & DROP
     ================================================ */
  $$(".drop-zone").forEach((zone) => {
    const input = zone.querySelector('input[type="file"]');
    const fileNameEl = zone.querySelector(".file-name");

    zone.addEventListener("click", () => input && input.click());
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("dragover"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
    zone.addEventListener("drop", (e) => {
      e.preventDefault();
      zone.classList.remove("dragover");
      if (e.dataTransfer.files.length) {
        selectedFile = e.dataTransfer.files[0];
        if (fileNameEl) { fileNameEl.textContent = selectedFile.name; fileNameEl.style.display = "block"; }
      }
    });
    if (input) {
      input.addEventListener("change", () => {
        if (input.files.length) {
          selectedFile = input.files[0];
          if (fileNameEl) { fileNameEl.textContent = selectedFile.name; fileNameEl.style.display = "block"; }
        }
      });
    }
  });

  /* ================================================
     ANALYZE
     ================================================ */
  analyzeBtn.addEventListener("click", analyze);

  async function analyze() {
    hideError();
    resultsEl.style.display = "none";

    const formData = new FormData();
    let hasInput = false;

    if (currentTab === "text") {
      const val = ($("#textInput") || {}).value || "";
      if (!val.trim()) return showError("Please enter some text to analyze.");
      formData.append("text", val.trim());
      hasInput = true;
    } else if (currentTab === "url") {
      const val = ($("#urlInput") || {}).value || "";
      if (!val.trim()) return showError("Please enter a URL to analyze.");
      if (!val.startsWith("http://") && !val.startsWith("https://"))
        return showError("URL must start with http:// or https://");
      formData.append("url", val.trim());
      hasInput = true;
    } else if (currentTab === "image") {
      if (!selectedFile) return showError("Please select or drop an image file.");
      formData.append("image", selectedFile);
      hasInput = true;
    } else if (currentTab === "audio") {
      if (!selectedFile) return showError("Please select or drop an audio file.");
      formData.append("audio", selectedFile);
      hasInput = true;
    }

    if (!hasInput) return showError("No input provided.");

    const offlineMode = $("#offlineModeToggle") ? $("#offlineModeToggle").checked : false;
    formData.append("offline_mode", offlineMode);

    analyzeBtn.classList.add("loading");
    analyzeBtn.disabled = true;

    // Reset timeline progress and show only the timeline card
    const timelineCard = $("#agentTimelineCard");
    timelineCard.style.display = "block";
    resetTimeline();

    // Hide other results cards during loading
    $("#verdictCard").style.display = "none";
    $$("#results > .section-card:not(.agent-timeline-card)").forEach(el => el.style.display = "none");
    resultsEl.style.display = "block";
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });

    try {
      const res = await fetch(API, { method: "POST", body: formData });
      
      if (!res.ok) {
        let errMsg = "Analysis failed.";
        try {
          const data = await res.json();
          errMsg = data.error || errMsg;
        } catch(e) {}
        showError(errMsg);
        timelineCard.style.display = "none";
        resultsEl.style.display = "none";
        return;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        // Keep the last partial line in the buffer
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const event = JSON.parse(line);
            handlePipelineEvent(event);
          } catch (e) {
            console.error("Error parsing JSON line", e, line);
          }
        }
      }

      if (buffer.trim()) {
        try {
          const event = JSON.parse(buffer);
          handlePipelineEvent(event);
        } catch (e) {
          console.error("Error parsing trailing JSON buffer", e);
        }
      }

    } catch (err) {
      console.error(err);
      showError("Connection error. Please try again.");
      timelineCard.style.display = "none";
      resultsEl.style.display = "none";
    } finally {
      analyzeBtn.classList.remove("loading");
      analyzeBtn.disabled = false;
    }
  }

  /* ================================================
     AGENT PIPELINE TIMELINE EVENTS
     ================================================ */
  function resetTimeline() {
    const steps = ["ingesting", "detecting", "scoring", "shielding"];
    steps.forEach(step => {
      const el = $(`#step-${step}`);
      if (el) {
        el.className = "timeline-step";
        const statusEl = $(`#status-${step}`);
        if (statusEl) statusEl.textContent = "Waiting...";
      }
    });
  }

  function handlePipelineEvent(event) {
    const status = event.status;
    const msg = event.message;

    if (status === "error") {
      showError(msg || "Pipeline error occurred.");
      $("#agentTimelineCard").style.display = "none";
      resultsEl.style.display = "none";
      return;
    }

    if (status === "ingesting") {
      setStepActive("ingesting", msg);
    } else if (status === "ingested") {
      setStepCompleted("ingesting", msg);
    } else if (status === "detecting") {
      setStepActive("detecting", msg);
    } else if (status === "detected") {
      setStepCompleted("detecting", msg);
    } else if (status === "scoring") {
      setStepActive("scoring", msg);
    } else if (status === "scored") {
      setStepCompleted("scoring", msg);
    } else if (status === "shielding") {
      setStepActive("shielding", msg);
    } else if (status === "shielded") {
      setStepCompleted("shielding", msg);
    } else if (status === "complete") {
      const result = event.result;
      const isOffline = result.certainty === "OFFLINE_MODE";
      
      // Mark all timeline steps completed
      const steps = ["ingesting", "detecting", "scoring", "shielding"];
      steps.forEach(step => {
        const el = $(`#step-${step}`);
        if (el) {
          if (isOffline) {
            el.className = "timeline-step offline-complete";
            const statusEl = $(`#status-${step}`);
            if (statusEl) {
              const offlineMsgs = {
                "ingesting": "Bypassed (Offline)",
                "detecting": "Local Regex Engine",
                "scoring": "Local Rule Score",
                "shielding": "Local Advice Template"
              };
              statusEl.textContent = offlineMsgs[step];
            }
          } else if (!el.classList.contains("completed")) {
            setStepCompleted(step, "Complete");
          }
        }
      });

      // Show other sections with smooth animations
      $("#verdictCard").style.display = "flex";
      $$("#results > .section-card").forEach(el => el.style.display = "block");

      // Render the final result object
      renderResults(result);
    }
  }

  function setStepActive(step, text) {
    const el = $(`#step-${step}`);
    if (el) {
      el.className = "timeline-step active";
      const statusEl = $(`#status-${step}`);
      if (statusEl) statusEl.textContent = text;
    }
  }

  function setStepCompleted(step, text) {
    const el = $(`#step-${step}`);
    if (el) {
      el.className = "timeline-step completed";
      const statusEl = $(`#status-${step}`);
      if (statusEl) statusEl.textContent = text;
    }
  }

  /* ================================================
     ERROR DISPLAY
     ================================================ */
  function showError(msg) {
    errorToast.textContent = msg;
    errorToast.style.display = "block";
    errorToast.scrollIntoView({ behavior: "smooth", block: "center" });
  }
  function hideError() { errorToast.style.display = "none"; }

  /* ================================================
     RENDER RESULTS
     ================================================ */
  function renderResults(d) {
    const score = d.fake_probability ?? 0;
    const level = d.risk_level || "Safe";
    const tactics = d.manipulation_tactics || [];
    const plainEnglish = d.plain_english_explanation || d.explanation || "";
    const recommendation = d.recommendation || "";
    const redFlags = d.red_flags || [];
    const sysFlags = d.system_flags || [];
    const breakdown = d.score_breakdown || {};
    const certainty = d.certainty || "";

    const levelColor = getLevelColor(level);

    /* ── Verdict Card ── */
    const verdictCard = $("#verdictCard");
    verdictCard.style.background = levelColor.bg;
    verdictCard.style.borderColor = levelColor.border;

    /* Gauge */
    animateGauge(score, levelColor.main);

    /* Verdict Text */
    $("#verdictLevel").textContent = level;
    $("#verdictLevel").style.color = levelColor.main;
    $("#verdictCredibility").textContent =
      (d.overall_credibility ? "Credibility: " + d.overall_credibility : "") +
      (d.input_type ? " | Input: " + d.input_type.toUpperCase() : "");

    const certEl = $("#verdictCertainty");
    const certText = certainty.split("—")[0].trim().replace(/_/g, " ");
    certEl.textContent = certText;
    certEl.style.background = certainty.startsWith("CONFIDENT")
      ? "rgba(16,185,129,0.15)" : "rgba(245,158,11,0.15)";
    certEl.style.color = certainty.startsWith("CONFIDENT")
      ? "var(--safe)" : "var(--medium)";

    /* 3D Risk Score Dimensions Dashboard */
    const emotional = breakdown.emotional_manipulation || 0;
    const deception = breakdown.deception || 0;
    const coercion = breakdown.coercion || 0;

    $("#dimEmotional").textContent = emotional + "%";
    $("#dimDeception").textContent = deception + "%";
    $("#dimCoercion").textContent = coercion + "%";

    setDimColor("emotional", emotional);
    setDimColor("deception", deception);
    setDimColor("coercion", coercion);

    /* ── Manipulation Tactics ── */
    const tacticsContainer = $("#tacticsContainer");
    if (tactics.length === 0) {
      tacticsContainer.innerHTML = '<div class="no-tactics">No manipulation tactics detected in this content.</div>';
    } else {
      tacticsContainer.innerHTML = tactics.map((t) => `
        <div class="tactic-card severity-${t.severity || 'low'}">
          <div class="tactic-header">
            <span class="tactic-name">${esc(t.tactic)}</span>
            <span class="tactic-badge ${t.severity || 'low'}">${(t.severity || 'low').toUpperCase()}</span>
          </div>
          <div class="tactic-desc">${esc(t.description)}</div>
          ${t.evidence && !t.evidence.startsWith("Detected via") ?
            `<div class="tactic-evidence">"${esc(t.evidence)}"</div>` : ""}
        </div>
      `).join("");
    }

    /* ── Bilingual English and Tamil Explanations ── */
    $("#plainEnglish").textContent = plainEnglish;

    const tamilExpl = d.tamil_explanation || "";
    const tamilExplEl = $("#tamilExplanation");
    if (tamilExpl) {
      tamilExplEl.textContent = tamilExpl;
      tamilExplEl.previousElementSibling.style.display = "block";
      tamilExplEl.style.display = "block";
      const div = tamilExplEl.parentElement.querySelector(".tamil-divider");
      if (div) div.style.display = "block";
    } else {
      tamilExplEl.style.display = "none";
      tamilExplEl.previousElementSibling.style.display = "none";
      const div = tamilExplEl.parentElement.querySelector(".tamil-divider");
      if (div) div.style.display = "none";
    }

    /* ── Recommendations ── */
    const recEl = $("#recommendation");
    if (recommendation) {
      recEl.textContent = recommendation;
      recEl.parentElement.style.display = "block";
    } else {
      recEl.parentElement.style.display = "none";
    }

    const tamilRec = d.tamil_recommendation || "";
    const tamilRecEl = $("#tamilRecommendation");
    if (tamilRec) {
      tamilRecEl.textContent = tamilRec;
      tamilRecEl.style.display = "block";
      const div = tamilRecEl.parentElement.querySelector(".tamil-divider");
      if (div) div.style.display = "block";
    } else {
      tamilRecEl.style.display = "none";
      const div = tamilRecEl.parentElement.querySelector(".tamil-divider");
      if (div) div.style.display = "none";
    }

    /* ── Score Breakdown ── */
    const llm = breakdown.llm_score || d.llm_score || 0;
    const pattern = breakdown.pattern_score || d.pattern_score || 0;
    const flags = breakdown.flags_score || 0;
    const urlRule = breakdown.url_rule_score || d.url_rule_score || 0;

    setBar("barLLM", llm);
    setBar("barPattern", Math.round((pattern / 70) * 100));
    setBar("barFinal", score);

    const urlBarRow = $("#urlBarRow");
    if (d.input_type === "url") {
      urlBarRow.style.display = "flex";
      setBar("urlBarRow", urlRule);
    } else {
      urlBarRow.style.display = "none";
    }

    /* ── System Flags ── */
    const allFlags = [...new Set([...sysFlags, ...redFlags])];
    const flagsContainer = $("#flagsContainer");
    if (allFlags.length === 0) {
      flagsContainer.innerHTML = '<div class="no-tactics">No warning signals detected.</div>';
    } else {
      flagsContainer.innerHTML = allFlags.map((f) => `
        <div class="flag-item">
          <span class="flag-icon">${getFlagIcon(f)}</span>
          <span>${esc(f)}</span>
        </div>
      `).join("");
    }

    /* ── Extracted Content ── */
    const extractedSection = $("#extractedSection");
    if (d.input_type === "image" && d.extracted_text) {
      extractedSection.style.display = "block";
      $("#extractedTitle").textContent = "Extracted Text (OCR)";
      $("#extractedMeta").textContent = `${d.ocr_char_count || 0} chars | Confidence: ${d.ocr_confidence || 0}% | Quality: ${d.ocr_quality || "unknown"}`;
      $("#extractedContent").textContent = d.extracted_text;
    } else if (d.input_type === "audio" && d.transcription) {
      extractedSection.style.display = "block";
      $("#extractedTitle").textContent = "Transcription (Whisper)";
      $("#extractedMeta").textContent = `${d.audio_char_count || 0} chars | Confidence: ${d.audio_confidence || 0}% | Quality: ${d.audio_quality || "unknown"}`;
      $("#extractedContent").textContent = d.transcription;
    } else if (d.input_type === "url" && d.domain_analysis) {
      extractedSection.style.display = "block";
      const da = d.domain_analysis;
      $("#extractedTitle").textContent = "Domain Analysis";
      $("#extractedMeta").textContent = `Method: ${d.extraction_method || "N/A"} | Status: ${d.extraction_status || "N/A"}`;
      $("#extractedContent").textContent =
        `Domain: ${da.domain}\nHTTPS: ${da.is_https}\nTrusted: ${da.trusted_domain}\nSuspicious TLD: ${da.suspicious_tld}\nDomain Age: ${da.domain_age_days !== null ? da.domain_age_days + " days" : "Unknown"}`;
    } else {
      extractedSection.style.display = "none";
    }

    /* ── Source Info ── */
    $("#sourceInfo").textContent =
      `Source: ${d.source || "N/A"} | Response: ${d.response_time ? d.response_time + "s" : "N/A"}${d.cached ? " (cached)" : ""}`;

    /* Show results */
    resultsEl.style.display = "block";
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function setDimColor(dimName, val) {
    const pill = $(`.dimension-pill[data-dim="${dimName}"]`);
    if (!pill) return;
    let color = "var(--safe)";
    if (val >= 80) color = "var(--critical)";
    else if (val >= 60) color = "var(--high)";
    else if (val >= 35) color = "var(--medium)";
    else if (val >= 15) color = "var(--low)";
    pill.style.borderLeftColor = color;
    const valEl = pill.querySelector(".dim-val");
    if (valEl) valEl.style.color = color;
  }

  /* ================================================
     GAUGE ANIMATION
     ================================================ */
  function animateGauge(score, color) {
    const circle = $("#gaugeFill");
    const numberEl = $("#gaugeNumber");
    const r = 52;
    const c = 2 * Math.PI * r;
    circle.setAttribute("r", r);
    circle.style.strokeDasharray = c;
    circle.style.stroke = color;

    /* Animate from 0 */
    const target = c - (score / 100) * c;
    circle.style.strokeDashoffset = c;
    numberEl.textContent = "0";
    numberEl.style.color = color;

    requestAnimationFrame(() => {
      circle.style.strokeDashoffset = target;
    });

    /* Count up number */
    let current = 0;
    const step = Math.max(1, Math.floor(score / 40));
    const interval = setInterval(() => {
      current += step;
      if (current >= score) { current = score; clearInterval(interval); }
      numberEl.textContent = current;
    }, 25);
  }

  /* ================================================
     HELPERS
     ================================================ */
  function setBar(id, value) {
    const el = document.getElementById(id);
    if (!el) return;
    const fill = el.querySelector(".bar-fill");
    const valEl = el.querySelector(".bar-value");
    if (fill) setTimeout(() => { fill.style.width = value + "%"; }, 100);
    if (valEl) valEl.textContent = Math.round(value);
  }

  function getLevelColor(level) {
    const map = {
      "Safe":             { main: "var(--safe)",     bg: "var(--safe-bg)",     border: "rgba(16,185,129,0.2)" },
      "Low":              { main: "var(--low)",      bg: "var(--low-bg)",      border: "rgba(59,130,246,0.2)" },
      "Medium":           { main: "var(--medium)",   bg: "var(--medium-bg)",   border: "rgba(245,158,11,0.2)" },
      "High":             { main: "var(--high)",     bg: "var(--high-bg)",     border: "rgba(239,68,68,0.2)" },
      "Critical":         { main: "var(--critical)", bg: "var(--critical-bg)", border: "rgba(220,38,38,0.25)" },
      "No Significant Risk": { main: "var(--safe)",  bg: "var(--safe-bg)",     border: "rgba(16,185,129,0.2)" },
    };
    return map[level] || map["Safe"];
  }

  function getFlagIcon(flag) {
    const fl = flag.toLowerCase();
    if (fl.includes("trust") || fl.includes("safe")) return '<svg width="14" height="14" fill="none" stroke="#10b981" stroke-width="2" viewBox="0 0 24 24"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>';
    if (fl.includes("fear") || fl.includes("threat") || fl.includes("danger")) return '<svg width="14" height="14" fill="none" stroke="#ef4444" stroke-width="2" viewBox="0 0 24 24"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>';
    return '<svg width="14" height="14" fill="none" stroke="#f59e0b" stroke-width="2" viewBox="0 0 24 24"><path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
  }

  function esc(s) {
    if (!s) return "";
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }
})();
