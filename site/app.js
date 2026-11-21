// Hosted waitlist endpoint. Override by setting window.ENKI_WAITLIST_ENDPOINT
// before this script loads, or edit the default below.
const WAITLIST_ENDPOINT =
  window.ENKI_WAITLIST_ENDPOINT || "http://localhost:8080/v1/waitlist";

const form = document.getElementById("waitlist-form");
const status = document.getElementById("waitlist-status");
const submit = document.getElementById("waitlist-submit");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(form);
  const payload = {
    email: String(data.get("email") || "").trim(),
    role: String(data.get("role") || "").trim(),
    use_case: String(data.get("use_case") || "").trim(),
  };
  if (!payload.email) {
    status.textContent = "Enter a work email.";
    status.style.color = "var(--red)";
    return;
  }

  submit.disabled = true;
  submit.textContent = "Submitting…";
  status.textContent = "";
  try {
    const res = await fetch(WAITLIST_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await res.json().catch(() => ({}));
    if (res.status === 201 || res.status === 200) {
      status.style.color = "var(--green)";
      status.textContent =
        body.status === "already subscribed"
          ? "You are already on the list — we will be in touch."
          : "You are on the list. We will invite beta cohorts by email.";
      form.reset();
    } else {
      throw new Error(body.error || `request failed (${res.status})`);
    }
  } catch (err) {
    status.style.color = "var(--red)";
    status.textContent =
      "Could not submit (" + (err.message || "network error") + "). " +
      "You can also open an issue on GitHub to request access.";
  } finally {
    submit.disabled = false;
    submit.textContent = "Request access";
  }
});
