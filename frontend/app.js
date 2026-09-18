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
  /* ================================================
     3D CANVAS RISK GAUGE ANIMATION
     ================================================ */
  let gaugeAnimFrame = null;

  function animateGauge(targetScore, colorStr) {
    const canvas = document.getElementById("riskGaugeCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width, H = canvas.height;

    let currentVal = 0;
    const startTime = performance.now();
    const duration = 800; // ms

    if (gaugeAnimFrame) cancelAnimationFrame(gaugeAnimFrame);

    function renderFrame(now) {
      const elapsed = now - startTime;
      const progress = Math.min(1, elapsed / duration);
      // Ease out cubic
      const easedProgress = 1 - Math.pow(1 - progress, 3);
      currentVal = targetScore * easedProgress;

      drawGaugeCanvas(ctx, W, H, currentVal, targetScore);

      if (progress < 1) {
        gaugeAnimFrame = requestAnimationFrame(renderFrame);
      }
    }

    gaugeAnimFrame = requestAnimationFrame(renderFrame);
  }

  function drawGaugeCanvas(ctx, W, H, val, finalVal) {
    ctx.clearRect(0, 0, W, H);

    const cx = W / 2;
    const cy = H - 24;
    const R = 85;
    const trackW = 14;
    const startA = Math.PI;
    const endA = 2 * Math.PI;
    const valA = startA + (val / 100) * Math.PI;

    // Color determination
    const col = val < 35 ? "#00ffaa" : val < 65 ? "#ffb700" : "#ff4d4d";

    // ── Tick Marks & Labels ──
    for (let i = 0; i <= 10; i++) {
      const a = startA + (i / 10) * Math.PI;
      const isMajor = i % 2 === 0;
      const r1 = R + trackW + 4;
      const r2 = r1 + (isMajor ? 8 : 4);
      ctx.beginPath();
      ctx.moveTo(cx + Math.cos(a) * r1, cy + Math.sin(a) * r1);
      ctx.lineTo(cx + Math.cos(a) * r2, cy + Math.sin(a) * r2);
      ctx.strokeStyle = isMajor ? "rgba(0, 240, 255, 0.6)" : "rgba(0, 240, 255, 0.25)";
      ctx.lineWidth = isMajor ? 2 : 1;
      ctx.stroke();
    }

    // Tick numerical labels
    const labels = [0, 25, 50, 75, 100];
    ctx.font = "600 9px 'Exo 2', sans-serif";
    ctx.fillStyle = "rgba(0, 240, 255, 0.5)";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    labels.forEach(pct => {
      const a = startA + (pct / 100) * Math.PI;
      const lr = R + trackW + 18;
      ctx.fillText(pct.toString(), cx + Math.cos(a) * lr, cy + Math.sin(a) * lr);
    });

    // ── Outer Background Arc ──
    ctx.beginPath();
    ctx.arc(cx, cy, R, startA, endA);
    ctx.strokeStyle = "rgba(255, 255, 255, 0.07)";
    ctx.lineWidth = trackW;
    ctx.lineCap = "round";
    ctx.stroke();

    // ── Active Colored Arc ──
    if (val > 0) {
      const grad = ctx.createLinearGradient(
        cx + Math.cos(startA) * R, cy + Math.sin(startA) * R,
        cx + Math.cos(valA) * R, cy + Math.sin(valA) * R
      );
      grad.addColorStop(0, "#00ffaa");
      grad.addColorStop(0.5, "#ffb700");
      grad.addColorStop(1, "#ff4d4d");

      ctx.beginPath();
      ctx.arc(cx, cy, R, startA, valA);
      ctx.strokeStyle = grad;
      ctx.lineWidth = trackW;
      ctx.lineCap = "round";
      ctx.shadowColor = col;
      ctx.shadowBlur = 12;
      ctx.stroke();
      ctx.shadowBlur = 0;
    }

    // ── Animated Metallic Needle ──
    const nA = startA + (val / 100) * Math.PI;
    const nLen = R - 12;
    const nBase = 10;
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(nA);
    ctx.beginPath();
    ctx.moveTo(0, -nBase / 2);
    ctx.lineTo(nLen, 0);
    ctx.lineTo(0, nBase / 2);
    ctx.closePath();
    ctx.fillStyle = col;
    ctx.shadowColor = col;
    ctx.shadowBlur = 14;
    ctx.fill();
    ctx.restore();

    // ── Pivot Center ──
    ctx.beginPath();
    ctx.arc(cx, cy, 8, 0, Math.PI * 2);
    ctx.fillStyle = "#070c1e";
    ctx.fill();
    ctx.beginPath();
    ctx.arc(cx, cy, 5, 0, Math.PI * 2);
    ctx.fillStyle = col;
    ctx.shadowColor = col;
    ctx.shadowBlur = 8;
    ctx.fill();
    ctx.shadowBlur = 0;

    // ── Center Number Score ──
    ctx.textAlign = "center";
    ctx.textBaseline = "alphabetic";
    ctx.font = "800 24px 'Orbitron', sans-serif";
    ctx.fillStyle = col;
    ctx.shadowColor = col;
    ctx.shadowBlur = 16;
    ctx.fillText(Math.round(val) + "%", cx, cy - 20);
    ctx.shadowBlur = 0;

    // ── Sub-Label ──
    const riskTxt = finalVal < 15 ? "SAFE" : finalVal < 35 ? "LOW RISK" : finalVal < 60 ? "MODERATE" : finalVal < 80 ? "HIGH RISK" : "CRITICAL";
    ctx.font = "700 9px 'Exo 2', sans-serif";
    ctx.fillStyle = "rgba(0, 240, 255, 0.55)";
    ctx.letterSpacing = "1.5px";
    ctx.fillText(riskTxt, cx, cy - 6);
  }

  /* ================================================
     AMBIENT CYBER BACKGROUND PARTICLES CANVAS
     ================================================ */
  function initBgCanvas() {
    const canvas = document.getElementById("bgCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let W = canvas.width = window.innerWidth;
    let H = canvas.height = window.innerHeight;

    window.addEventListener("resize", () => {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    });

    const particles = Array.from({ length: 45 }, () => ({
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 2 + 1,
      alpha: Math.random() * 0.5 + 0.2
    }));

    function loopBg() {
      ctx.clearRect(0, 0, W, H);

      // Draw grid points & connections
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = W;
        if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H;
        if (p.y > H) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 240, 255, ${p.alpha})`;
        ctx.fill();

        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dist = Math.hypot(p.x - p2.x, p.y - p2.y);
          if (dist < 130) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(0, 240, 255, ${0.15 * (1 - dist / 130)})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      requestAnimationFrame(loopBg);
    }

    loopBg();
  }

  /* ================================================
     PARALLAX 3D CARD TILT EFFECT
     ================================================ */
  function init3DTilt() {
    const cards = document.querySelectorAll(".glass-tilt, .input-panel, .section-card");

    cards.forEach(card => {
      card.addEventListener("mousemove", e => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;

        const rx = (-y / rect.height) * 8; // deg
        const ry = (x / rect.width) * 8;  // deg

        card.style.transform = `perspective(1000px) rotateX(${rx}deg) rotateY(${ry}deg) scale3d(1.01, 1.01, 1.01)`;
      });

      card.addEventListener("mouseleave", () => {
        card.style.transform = "perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)";
      });
    });
  }

  // Initialize interactive features on load
  document.addEventListener("DOMContentLoaded", () => {
    initBgCanvas();
    init3DTilt();
  });

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
      "Safe":             { main: "var(--safe)",     bg: "var(--safe-bg)",     border: "rgba(0, 255, 170, 0.25)" },
      "Low":              { main: "var(--low)",      bg: "var(--low-bg)",      border: "rgba(56, 189, 248, 0.25)" },
      "Medium":           { main: "var(--medium)",   bg: "var(--medium-bg)",   border: "rgba(255, 183, 0, 0.25)" },
      "High":             { main: "var(--high)",     bg: "var(--high-bg)",     border: "rgba(255, 77, 77, 0.25)" },
      "Critical":         { main: "var(--critical)", bg: "var(--critical-bg)", border: "rgba(244, 63, 94, 0.3)" },
      "No Significant Risk": { main: "var(--safe)",  bg: "var(--safe-bg)",     border: "rgba(0, 255, 170, 0.25)" },
    };
    return map[level] || map["Safe"];
  }

  function getFlagIcon(flag) {
    const fl = flag.toLowerCase();
    if (fl.includes("trust") || fl.includes("safe")) return '<svg width="14" height="14" fill="none" stroke="#00ffaa" stroke-width="2" viewBox="0 0 24 24"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>';
    if (fl.includes("fear") || fl.includes("threat") || fl.includes("danger")) return '<svg width="14" height="14" fill="none" stroke="#ff4d4d" stroke-width="2" viewBox="0 0 24 24"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>';
    return '<svg width="14" height="14" fill="none" stroke="#ffb700" stroke-width="2" viewBox="0 0 24 24"><path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>';
  }

  function esc(s) {
    if (!s) return "";
    const d = document.createElement("div");
    d.textContent = s;
    return d.innerHTML;
  }
})();

