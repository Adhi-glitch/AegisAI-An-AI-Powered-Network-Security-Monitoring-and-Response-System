const signinForm = document.getElementById("signin-form");
const signinError = document.getElementById("signin-error");
const signinSubmit = document.getElementById("signin-submit");
const tokenKey = "aegisai-capture-token";

function nextPath() {
  const next = new URLSearchParams(window.location.search).get("next");
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/dashboard";
}

async function currentSession() {
  const token = localStorage.getItem(tokenKey);
  if (!token) return false;
  const response = await fetch("/api/v1/auth/me", { headers: { Authorization: `Bearer ${token}` } });
  if (!response.ok) {
    localStorage.removeItem(tokenKey);
    return false;
  }
  window.location.replace("/dashboard");
  return true;
}

if (new URLSearchParams(window.location.search).get("switch") !== "1") {
  currentSession().catch(() => localStorage.removeItem(tokenKey));
}

signinForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  signinError.textContent = "";
  signinSubmit.disabled = true;
  signinSubmit.querySelector("span:first-child").textContent = "Checking access...";

  const fields = new URLSearchParams({
    username: document.getElementById("signin-username").value,
    password: document.getElementById("signin-password").value,
  });

  try {
    const response = await fetch("/api/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: fields,
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Unable to sign in.");

    localStorage.setItem(tokenKey, result.access_token);
    document.getElementById("signin-password").value = "";
    window.location.assign(nextPath());
  } catch (error) {
    signinError.textContent = error.message || "Unable to sign in. Try again.";
    signinSubmit.disabled = false;
    signinSubmit.querySelector("span:first-child").textContent = "Continue to console";
  }
});