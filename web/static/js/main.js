"use strict";

// トースト通知
function showToast(msg, type = "success") {
  const icon = type === "success" ? "✅" : type === "error" ? "❌" : "ℹ️";
  const id = "toast-" + Date.now();
  const html = `
    <div id="${id}" class="toast align-items-center border-0 mb-2" role="alert">
      <div class="d-flex">
        <div class="toast-body">${icon} ${msg}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>`;
  document.getElementById("toastContainer").insertAdjacentHTML("beforeend", html);
  const el = document.getElementById(id);
  const toast = new bootstrap.Toast(el, { delay: 4000 });
  toast.show();
  el.addEventListener("hidden.bs.toast", () => el.remove());
}

// ポイント更新
function updatePoints(pts) {
  const el = document.getElementById("nav-points");
  if (el && pts !== undefined) el.textContent = pts;
}

// マークダウン → HTML（簡易レンダラー）
function renderMarkdown(md) {
  return md
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/```[\w]*\n([\s\S]*?)```/g, "<pre><code>$1</code></pre>")
    .replace(/^\| (.+) \|$/gm, (_, row) => {
      const cells = row.split(" | ").map(c => `<td>${c}</td>`).join("");
      return `<tr>${cells}</tr>`;
    })
    .replace(/^> (.+)$/gm, "<blockquote>$1</blockquote>")
    .replace(/^- \[ \] (.+)$/gm, '<li><input type="checkbox" disabled> $1</li>')
    .replace(/^- \[x\] (.+)$/gm, '<li><input type="checkbox" checked disabled> $1</li>')
    .replace(/^- (.+)$/gm, "<li>$1</li>")
    .replace(/^(\d+)\. (.+)$/gm, "<li>$2</li>")
    .replace(/\[(.+?)\]\((.+?)\)/g, '<a href="$2" target="_blank">$1</a>')
    .replace(/\n\n/g, "</p><p>")
    .replace(/^(?!<[hpulbctr])/gm, "");
}
