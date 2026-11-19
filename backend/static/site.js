const motionReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const canvas = document.getElementById("signal-canvas");

if (canvas && !motionReduced) {
  const context = canvas.getContext("2d");
  const points = [];
  let frame = 0;

  function resizeSignalField() {
    const bounds = canvas.getBoundingClientRect();
    const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
    canvas.width = Math.round(bounds.width * ratio);
    canvas.height = Math.round(bounds.height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    points.length = 0;
    const count = Math.min(48, Math.max(18, Math.round(bounds.width / 20)));
    for (let index = 0; index < count; index += 1) {
      points.push({
        x: Math.random() * bounds.width,
        y: Math.random() * bounds.height,
        dx: (Math.random() - 0.5) * 0.16,
        dy: (Math.random() - 0.5) * 0.16,
        phase: Math.random() * Math.PI * 2,
      });
    }
  }

  function drawSignalField() {
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    context.clearRect(0, 0, width, height);
    for (let left = 0; left < points.length; left += 1) {
      const point = points[left];
      point.x += point.dx;
      point.y += point.dy;
      if (point.x < 0 || point.x > width) point.dx *= -1;
      if (point.y < 0 || point.y > height) point.dy *= -1;
      point.phase += 0.01;
      for (let right = left + 1; right < points.length; right += 1) {
        const other = points[right];
        const distance = Math.hypot(point.x - other.x, point.y - other.y);
        if (distance < 122) {
          context.strokeStyle = `rgba(85, 221, 169, ${(1 - distance / 122) * 0.17})`;
          context.lineWidth = 0.7;
          context.beginPath();
          context.moveTo(point.x, point.y);
          context.lineTo(other.x, other.y);
          context.stroke();
        }
      }
      const pulse = 1.1 + (Math.sin(point.phase) + 1) * 0.65;
      context.fillStyle = "rgba(120, 230, 188, 0.48)";
      context.beginPath();
      context.arc(point.x, point.y, pulse, 0, Math.PI * 2);
      context.fill();
    }
    frame = window.requestAnimationFrame(drawSignalField);
  }

  resizeSignalField();
  drawSignalField();
  window.addEventListener("resize", resizeSignalField, { passive: true });
  window.addEventListener("pagehide", () => window.cancelAnimationFrame(frame), { once: true });
}

const revealItems = document.querySelectorAll(".reveal");
if ("IntersectionObserver" in window && !motionReduced) {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        entry.target.classList.add("is-visible");
        observer.unobserve(entry.target);
      }
    }
  }, { threshold: 0.12 });
  revealItems.forEach((item) => observer.observe(item));
} else {
  revealItems.forEach((item) => item.classList.add("is-visible"));
}

const menuToggle = document.querySelector(".menu-toggle");
const siteNav = document.querySelector(".site-nav");
if (menuToggle && siteNav) {
  menuToggle.addEventListener("click", () => {
    const expanded = menuToggle.getAttribute("aria-expanded") === "true";
    menuToggle.setAttribute("aria-expanded", String(!expanded));
    menuToggle.setAttribute("aria-label", expanded ? "Open navigation" : "Close navigation");
    siteNav.classList.toggle("menu-open", !expanded);
  });
  siteNav.querySelectorAll(".nav-links a").forEach((link) => link.addEventListener("click", () => {
    siteNav.classList.remove("menu-open");
    menuToggle.setAttribute("aria-expanded", "false");
    menuToggle.setAttribute("aria-label", "Open navigation");
  }));
}