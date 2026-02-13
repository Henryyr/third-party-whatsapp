"use strict";

(function () {
  const STORAGE_KEY = "tpwa_config_v1";
  const REQUEST_TIMEOUT_MS = 12_000;

  const form = document.querySelector("form.card");
  if (!form) return;

  const vendorNoteEl = document.getElementById("vendorNote");
  const statusEl = document.getElementById("status");
  const statusTitleEl = document.getElementById("statusTitle");
  const statusBodyEl = document.getElementById("statusBody");

  const apiKeyEl = document.getElementById("apiKey");
  const secretKeyEl = document.getElementById("secretKey");
  const rememberEl = document.getElementById("rememberConfig");
  const testUrlEl = document.getElementById("testUrl");
  const sendUrlEl = document.getElementById("sendUrl");
  const btnTestEl = document.getElementById("btnTest");
  const btnSaveEl = document.getElementById("btnSave");

  const optInEl = document.getElementById("optIn");
  const includeOptOutEl = document.getElementById("includeOptOut");
  const confirmRequiredEl = document.getElementById("confirmRequired");
  const confirmWindowMinutesEl = document.getElementById(
    "confirmWindowMinutes",
  );

  const toEl = form.querySelector('input[name="to"]');
  const toTextEl = form.querySelector('textarea[name="to"]');
  const messageEl = form.querySelector('textarea[name="message"]');
  const scheduleAtEl = form.querySelector('input[name="scheduleAt"]');

  const vendorRadios = Array.from(
    form.querySelectorAll('input[name="vendor"]'),
  );
  const modeRadios = Array.from(form.querySelectorAll('input[name="mode"]'));

  function getCheckedValue(radios) {
    const checked = radios.find((r) => r && r.checked);
    return checked ? String(checked.value || "") : "";
  }

  function getVendor() {
    return getCheckedValue(vendorRadios) || "wablas";
  }

  function getMode() {
    return getCheckedValue(modeRadios) || "now";
  }

  function clearInvalid() {
    const fields = [
      apiKeyEl,
      secretKeyEl,
      testUrlEl,
      sendUrlEl,
      toEl,
      toTextEl,
      messageEl,
      scheduleAtEl,
    ];

    fields.forEach((el) => {
      if (!el) return;
      el.removeAttribute("aria-invalid");
    });
  }

  function markInvalid(el) {
    if (!el) return;
    el.setAttribute("aria-invalid", "true");
  }

  function setStatus(kind, title, body) {
    if (statusEl) {
      statusEl.classList.remove("ok", "warn", "error", "loading");
      if (kind) statusEl.classList.add(kind);
    }

    if (statusTitleEl) statusTitleEl.textContent = title || "";
    if (statusBodyEl) statusBodyEl.textContent = body || "";
  }

  function toSafeText(value) {
    return typeof value === "string" ? value : String(value ?? "");
  }

  function trimLong(text, maxLen) {
    const raw = toSafeText(text);
    if (raw.length <= maxLen) return raw;
    return `${raw.slice(0, maxLen)}\n…(dipotong ${raw.length - maxLen} karakter)`;
  }

  function prettyResponseText(text) {
    const raw = toSafeText(text).trim();
    if (!raw) return "";
    try {
      const obj = JSON.parse(raw);
      return JSON.stringify(obj, null, 2);
    } catch {
      return raw;
    }
  }

  async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...options, signal: controller.signal });
      return res;
    } finally {
      clearTimeout(timer);
    }
  }

  function readStorage() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.version !== 1) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  function writeStorage(data) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
      return true;
    } catch {
      return false;
    }
  }

  function clearStorage() {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
  }

  function vendorDefaults() {
    return { apiKey: "", secretKey: "", testUrl: "", sendUrl: "" };
  }

  function loadVendorConfig(vendor) {
    const store = readStorage();
    if (!store || !store.vendors || !store.vendors[vendor]) return null;
    return { ...vendorDefaults(), ...store.vendors[vendor] };
  }

  function saveVendorConfig(vendor, cfg) {
    const next = readStorage() || { version: 1, vendors: {} };
    next.version = 1;
    next.vendors = next.vendors || {};
    next.vendors[vendor] = { ...vendorDefaults(), ...cfg };
    return writeStorage(next);
  }

  function readConfigFromInputs() {
    return {
      apiKey: (apiKeyEl?.value || "").trim(),
      secretKey: (secretKeyEl?.value || "").trim(),
      testUrl: (testUrlEl?.value || "").trim(),
      sendUrl: (sendUrlEl?.value || "").trim(),
    };
  }

  function applyVendorConfig(vendor) {
    if (!rememberEl || !rememberEl.checked) return;
    const cfg = loadVendorConfig(vendor);
    if (!cfg) return;
    if (apiKeyEl) apiKeyEl.value = cfg.apiKey || "";
    if (secretKeyEl) secretKeyEl.value = cfg.secretKey || "";
    if (testUrlEl) testUrlEl.value = cfg.testUrl || "";
    if (sendUrlEl) sendUrlEl.value = cfg.sendUrl || "";
  }

  function suggestLocalUrlsIfEmpty(vendor) {
    const isSupported =
      vendor === "starseeder" || vendor === "starsender" || vendor === "wablas";
    if (!isSupported) return;
    if (!testUrlEl || !sendUrlEl) return;

    // If served from our backend, use same-origin URLs.
    if (
      window.location &&
      (window.location.protocol === "http:" ||
        window.location.protocol === "https:")
    ) {
      if (!testUrlEl.value.trim())
        testUrlEl.value = `${window.location.origin}/api/test`;
      if (!sendUrlEl.value.trim())
        sendUrlEl.value = `${window.location.origin}/api/send`;
      return;
    }

    // If opened via `file://`, default to localhost backend.
    if (!testUrlEl.value.trim())
      testUrlEl.value = "http://127.0.0.1:3000/api/test";
    if (!sendUrlEl.value.trim())
      sendUrlEl.value = "http://127.0.0.1:3000/api/send";
  }

  function updateVendorNote(vendor) {
    if (!vendorNoteEl) return;
    const note =
      vendor === "wablas"
        ? "Wablas dipilih. Isi konfigurasi, lalu gunakan tombol test untuk cek koneksi."
        : "StarSeeder dipilih. Untuk StarSender, API key = Device API key (header Authorization). Secret biasanya tidak dipakai.";
    vendorNoteEl.textContent = note;
  }

  function vendorNeedsSecret(vendor) {
    // StarSender docs: only Authorization (Device API key).
    // Keep secret optional for StarSender/StarSeeder to avoid blocking usage.
    return vendor === "wablas";
  }

  function normalizeSubscriberNumber(raw) {
    const digits = toSafeText(raw).replace(/\D/g, "");
    if (!digits) return "";

    let subscriber = digits;
    if (subscriber.startsWith("62")) subscriber = subscriber.slice(2);
    subscriber = subscriber.replace(/^0+/, "");
    return subscriber;
  }

  function formatE164Indonesia(raw) {
    const subscriber = normalizeSubscriberNumber(raw);
    if (!subscriber) return { subscriber: "", e164: "" };
    return { subscriber, e164: `+62${subscriber}` };
  }

  function getToRaw() {
    if (toTextEl) return toTextEl.value || "";
    if (toEl) return toEl.value || "";
    return "";
  }

  function parseRecipients(raw) {
    const text = toSafeText(raw);
    const parts = text
      .split(/[\s,;]+/)
      .map((p) => p.trim())
      .filter(Boolean);

    const seen = new Set();
    const out = [];
    for (const p of parts) {
      const e164 = formatE164Indonesia(p).e164;
      if (!e164) continue;
      if (seen.has(e164)) continue;
      seen.add(e164);
      out.push(e164);
    }
    return out;
  }

  function parseSchedule(value) {
    const local = (value || "").trim();
    if (!local) return { local: "", iso: "", epochMs: null };
    const date = new Date(local);
    const epochMs = Number.isFinite(date.getTime()) ? date.getTime() : null;
    const iso = epochMs === null ? "" : new Date(epochMs).toISOString();
    return { local, iso, epochMs };
  }

  function buildPayload() {
    const vendor = getVendor();
    const mode = getMode();
    const toList = parseRecipients(getToRaw());
    const to = { e164: toList[0] || "" };
    const message = toSafeText(messageEl?.value || "");

    const schedule =
      mode === "schedule" ? parseSchedule(scheduleAtEl?.value || "") : null;

    const includeOptOut = Boolean(includeOptOutEl && includeOptOutEl.checked);
    const optOutText = includeOptOut ? "\n\nBalas STOP untuk berhenti." : "";

    const requireConfirm =
      mode === "schedule" &&
      Boolean(confirmRequiredEl && confirmRequiredEl.checked);
    const confirmWindowMinutesRaw = Number.parseInt(
      confirmWindowMinutesEl?.value || "0",
      10,
    );
    const confirmWindowMinutes =
      Number.isFinite(confirmWindowMinutesRaw) && confirmWindowMinutesRaw > 0
        ? confirmWindowMinutesRaw
        : null;

    return {
      vendor,
      mode,
      to: to.e164,
      toList,
      message: `${message}${optOutText}`,
      scheduleAt: schedule,
      requireConfirm,
      confirmWindowMinutes,
    };
  }

  async function onTest() {
    clearInvalid();
    const vendor = getVendor();
    const cfg = readConfigFromInputs();
    const toList = parseRecipients(getToRaw());

    if (!cfg.apiKey) {
      markInvalid(apiKeyEl);
      apiKeyEl?.focus();
      setStatus(
        "error",
        "Gagal: API Key kosong",
        "Isi API Key lalu coba lagi.",
      );
      return;
    }

    if (vendorNeedsSecret(vendor) && !cfg.secretKey) {
      markInvalid(secretKeyEl);
      secretKeyEl?.focus();
      setStatus(
        "error",
        "Gagal: Secret Key kosong",
        "Isi Secret Key lalu coba lagi.",
      );
      return;
    }

    if (!cfg.testUrl) {
      setStatus(
        "warn",
        "Konfigurasi terlihat valid (offline)",
        "Isi Test URL (Advanced) untuk test live ke backend/vendor.",
      );
      return;
    }

    setStatus("loading", "Testing...", "Menghubungi endpoint test...");

    const headers = {
      "Content-Type": "application/json",
      "X-Vendor": vendor,
      "X-API-KEY": cfg.apiKey,
      "X-API-SECRET": cfg.secretKey,
    };

    const body = {
      action: "test",
      vendor,
      toList,
      at: new Date().toISOString(),
    };

    try {
      const res = await fetchWithTimeout(
        cfg.testUrl,
        {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        },
        REQUEST_TIMEOUT_MS,
      );

      const text = await res.text();
      const pretty = trimLong(prettyResponseText(text), 3000);

      if (!res.ok) {
        setStatus(
          "error",
          `Test gagal (${res.status})`,
          pretty || "Tidak ada response body.",
        );
        return;
      }

      setStatus(
        "ok",
        `Test berhasil (${res.status})`,
        pretty || "OK (response kosong).",
      );
    } catch (err) {
      const msg =
        err &&
        typeof err === "object" &&
        "name" in err &&
        err.name === "AbortError"
          ? "Request timeout."
          : toSafeText(err?.message || err);
      setStatus("error", "Test gagal (network)", msg);
    }
  }

  function onSave() {
    clearInvalid();

    if (!rememberEl || !rememberEl.checked) {
      setStatus(
        "warn",
        "Belum disimpan",
        "Centang 'Simpan di browser' untuk menyimpan konfigurasi.",
      );
      return;
    }

    const vendor = getVendor();
    const cfg = readConfigFromInputs();

    const ok = saveVendorConfig(vendor, cfg);
    if (!ok) {
      setStatus(
        "error",
        "Gagal menyimpan",
        "Browser memblokir penyimpanan (localStorage).",
      );
      return;
    }

    setStatus("ok", "Konfigurasi tersimpan", `Vendor: ${vendor}`);
  }

  async function onSubmit(e) {
    e.preventDefault();
    clearInvalid();

    const vendor = getVendor();
    const mode = getMode();
    const cfg = readConfigFromInputs();
    const payload = buildPayload();

    if (optInEl && !optInEl.checked) {
      markInvalid(optInEl);
      optInEl?.focus();
      setStatus(
        "error",
        "Gagal: butuh opt-in",
        "Centang pernyataan izin/opt-in sebelum kirim/jadwalkan pesan.",
      );
      return;
    }

    if (!cfg.apiKey) {
      markInvalid(apiKeyEl);
      apiKeyEl?.focus();
      setStatus(
        "error",
        "Gagal: API Key kosong",
        "Isi API Key lalu kirim lagi.",
      );
      return;
    }

    if (vendorNeedsSecret(vendor) && !cfg.secretKey) {
      markInvalid(secretKeyEl);
      secretKeyEl?.focus();
      setStatus(
        "error",
        "Gagal: Secret Key kosong",
        "Isi Secret Key lalu kirim lagi.",
      );
      return;
    }

    if (!payload.toList || payload.toList.length === 0) {
      if (toTextEl) {
        markInvalid(toTextEl);
        toTextEl?.focus();
      } else {
        markInvalid(toEl);
        toEl?.focus();
      }
      setStatus(
        "error",
        "Gagal: To kosong/invalid",
        "Isi minimal 1 nomor tujuan yang benar.",
      );
      return;
    }

    if (!payload.message.trim()) {
      markInvalid(messageEl);
      messageEl?.focus();
      setStatus("error", "Gagal: pesan kosong", "Isi message lalu kirim lagi.");
      return;
    }

    if (mode === "schedule") {
      if (!payload.scheduleAt || !payload.scheduleAt.local) {
        markInvalid(scheduleAtEl);
        scheduleAtEl?.focus();
        setStatus(
          "error",
          "Gagal: jadwal kosong",
          "Pilih tanggal & jam jadwal.",
        );
        return;
      }
    }

    if (!cfg.sendUrl) {
      const preview = {
        headers: {
          "X-Vendor": vendor,
          "X-API-KEY": "(diisi)",
          "X-API-SECRET": "(diisi)",
        },
        payload,
        note: "Isi Send URL (Advanced) untuk kirim request ke backend/vendor.",
      };
      setStatus(
        "ok",
        "Payload siap (belum dikirim)",
        JSON.stringify(preview, null, 2),
      );
      return;
    }

    // Schedule mode with recipient-confirm is a single backend call.
    if (payload.mode === "schedule" && payload.requireConfirm) {
      setStatus(
        "loading",
        "Mengirim permintaan konfirmasi...",
        "Backend akan kirim pesan konfirmasi ke penerima sekarang.",
      );

      const headers = {
        "Content-Type": "application/json",
        "X-Vendor": vendor,
        "X-API-KEY": cfg.apiKey,
        "X-API-SECRET": cfg.secretKey,
      };

      const body = {
        ...payload,
        sentAt: new Date().toISOString(),
      };

      try {
        const res = await fetchWithTimeout(
          cfg.sendUrl,
          {
            method: "POST",
            headers,
            body: JSON.stringify(body),
          },
          REQUEST_TIMEOUT_MS,
        );

        const text = await res.text();
        const pretty = trimLong(prettyResponseText(text), 8000);

        if (!res.ok) {
          setStatus(
            "error",
            `Gagal membuat konfirmasi (${res.status})`,
            pretty || "Tidak ada response body.",
          );
          return;
        }

        setStatus(
          "ok",
          "Konfirmasi terkirim",
          pretty || "OK (response kosong).",
        );
      } catch (err) {
        const msg =
          err &&
          typeof err === "object" &&
          "name" in err &&
          err.name === "AbortError"
            ? "Request timeout."
            : toSafeText(err?.message || err);
        setStatus("error", "Gagal (network)", msg);
      }
      return;
    }

    const SLEEP_BETWEEN_SEND_MS = 1600;

    async function sendOnce(toE164) {
      const headers = {
        "Content-Type": "application/json",
        "X-Vendor": vendor,
        "X-API-KEY": cfg.apiKey,
        "X-API-SECRET": cfg.secretKey,
      };

      const body = {
        ...payload,
        to: toE164,
        sentAt: new Date().toISOString(),
      };

      const res = await fetchWithTimeout(
        cfg.sendUrl,
        {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        },
        REQUEST_TIMEOUT_MS,
      );

      const text = await res.text();
      const pretty = trimLong(prettyResponseText(text), 2500);
      return { okHttp: res.ok, status: res.status, body: pretty };
    }

    const targets = payload.toList || [];
    const results = [];

    try {
      for (let i = 0; i < targets.length; i += 1) {
        const toE164 = targets[i];
        setStatus(
          "loading",
          `Mengirim... (${i + 1}/${targets.length})`,
          `Target: ${toE164}`,
        );

        const r = await sendOnce(toE164);
        results.push({
          to: toE164,
          status: r.status,
          ok: r.okHttp,
          body: r.body,
        });

        if (i < targets.length - 1) {
          await new Promise((resolve) =>
            setTimeout(resolve, SLEEP_BETWEEN_SEND_MS),
          );
        }
      }

      const okCount = results.filter((r) => r.ok).length;
      const failCount = results.length - okCount;
      const kind = failCount === 0 ? "ok" : okCount > 0 ? "warn" : "error";
      const title =
        failCount === 0
          ? `Kirim berhasil (${okCount}/${results.length})`
          : `Selesai (${okCount} sukses, ${failCount} gagal)`;
      setStatus(kind, title, JSON.stringify({ results }, null, 2));
    } catch (err) {
      const msg =
        err &&
        typeof err === "object" &&
        "name" in err &&
        err.name === "AbortError"
          ? "Request timeout."
          : toSafeText(err?.message || err);
      setStatus("error", "Kirim gagal (network)", msg);
    }
  }

  function init() {
    const store = readStorage();
    if (rememberEl && store) rememberEl.checked = true;

    updateVendorNote(getVendor());
    applyVendorConfig(getVendor());
    suggestLocalUrlsIfEmpty(getVendor());
    setStatus("", "Status: belum ditest", "");

    vendorRadios.forEach((r) => {
      r.addEventListener("change", () => {
        updateVendorNote(getVendor());
        if (rememberEl && rememberEl.checked) applyVendorConfig(getVendor());
        suggestLocalUrlsIfEmpty(getVendor());
      });
    });

    if (rememberEl) {
      rememberEl.addEventListener("change", () => {
        if (!rememberEl.checked) {
          clearStorage();
          setStatus(
            "warn",
            "Penyimpanan dimatikan",
            "Konfigurasi yang tersimpan di browser dihapus.",
          );
          return;
        }

        onSave();
      });
    }

    btnTestEl?.addEventListener("click", onTest);
    btnSaveEl?.addEventListener("click", onSave);

    form.addEventListener("submit", onSubmit);
    form.addEventListener("reset", () => {
      setTimeout(() => {
        clearInvalid();
        updateVendorNote(getVendor());
        applyVendorConfig(getVendor());
        setStatus("", "Status: belum ditest", "");
      }, 0);
    });
  }

  init();
})();
