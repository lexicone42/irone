/* HTMX configuration and toast notifications */

document.addEventListener("DOMContentLoaded", function () {
    // Set active nav link based on current URL
    const path = window.location.pathname;
    document.querySelectorAll(".nav-link").forEach(function (link) {
        if (link.getAttribute("href") === path) {
            link.classList.add("active");
        }
    });
});

// HTMX after-swap: auto-dismiss alerts after 5s
document.addEventListener("htmx:afterSwap", function (event) {
    const alerts = event.detail.target.querySelectorAll(".alert[data-auto-dismiss]");
    alerts.forEach(function (alert) {
        setTimeout(function () {
            alert.style.opacity = "0";
            setTimeout(function () { alert.remove(); }, 300);
        }, 5000);
    });
});
