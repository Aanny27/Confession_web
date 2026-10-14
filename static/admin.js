let csrfToken = "";
let adminPage = 1;
let logsPage = 1;

const loginSection = document.getElementById("login-section");
const dashboardSection = document.getElementById("dashboard-section");
const logoutBtn = document.getElementById("logout-btn");
const currentUserBadge = document.getElementById("current-user-badge");
const globalFeedback = document.getElementById("admin-global-feedback");

function showMsg(el, text, type = "error") {
  el.textContent = text;
  el.className = `field-feedback ${type}`;
}

function hideMsg(el) {
  el.textContent = "";
  el.className = "field-feedback hidden";
}

async function initCsrf() {
  const res = await fetch("/api/csrf", { credentials: "same-origin" });
  const data = await res.json();
  csrfToken = data.csrf_token;
}

function enterDashboard(username, role) {
  loginSection.classList.add("hidden");
  dashboardSection.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  const roleLabel = role === "owner" ? "Quản trị tối cao (Chủ dự án)" : "Admin duyệt bài";
  currentUserBadge.textContent = ` • Đang đăng nhập: ${username} [${roleLabel}]`;
  currentUserBadge.className = "";

  const tabUsers = document.getElementById("tab-btn-users");
  const tabLogs = document.getElementById("tab-btn-logs");
  if (role === "owner") {
    tabUsers.classList.remove("hidden");
    tabLogs.classList.remove("hidden");
  } else {
    tabUsers.classList.add("hidden");
    tabLogs.classList.add("hidden");
  }

  switchTab("confessions");
  loadAdminConfessions(1);
}

// ĐĂNG NHẬP 1 BƯỚC
document.getElementById("admin-login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const feedbackEl = document.getElementById("login-feedback");
  hideMsg(feedbackEl);

  const username = document.getElementById("admin-username").value.trim();
  const password = document.getElementById("admin-password").value;
  const btn = document.getElementById("login-btn");
  btn.disabled = true;

  try {
    const res = await fetch("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      credentials: "same-origin",
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (!res.ok) {
      showMsg(feedbackEl, data.detail || "Đăng nhập thất bại.", "error");
    } else {
      document.getElementById("admin-password").value = "";
      enterDashboard(data.username, data.role);
    }
  } finally {
    btn.disabled = false;
  }
});

function switchTab(tabName) {
  ["confessions", "users", "logs"].forEach((t) => {
    const btn = document.getElementById(`tab-btn-${t}`);
    const panel = document.getElementById(`tab-panel-${t}`);
    if (t === tabName) {
      btn.classList.add("active");
      panel.classList.remove("hidden");
    } else {
      btn.classList.remove("active");
      panel.classList.add("hidden");
    }
  });
}

document.getElementById("tab-btn-confessions").addEventListener("click", () => {
  switchTab("confessions");
  loadAdminConfessions(adminPage);
});

document.getElementById("tab-btn-users").addEventListener("click", () => {
  switchTab("users");
  loadUsersList();
});

document.getElementById("tab-btn-logs").addEventListener("click", () => {
  switchTab("logs");
  loadActivityLogs(1);
});

// TAB 1: DUYỆT CONFESSION (Đã đồng bộ hiển thị Danh mục & Tiêu đề)
async function loadAdminConfessions(page = 1) {
  const statusFilter = document.getElementById("status-filter").value;
  const query = encodeURIComponent(document.getElementById("search-input").value.trim());
  const listEl = document.getElementById("admin-confessions-list");

  const res = await fetch(
    `/api/admin/confessions?status_filter=${statusFilter}&q=${query}&page=${page}&page_size=10`,
    { credentials: "same-origin" }
  );
  if (res.status === 401 || res.status === 403) {
    window.location.reload();
    return;
  }

  const data = await res.json();
  listEl.replaceChildren();

  if (!data.items || data.items.length === 0) {
    const p = document.createElement("p");
    p.textContent = "Không có Confession nào khớp với bộ lọc.";
    listEl.appendChild(p);
  } else {
    data.items.forEach((item) => {
      const card = document.createElement("article");
      card.className = "confession-item";

      const meta = document.createElement("div");
      meta.className = "confession-meta";

      const leftSpan = document.createElement("span");
      const catLabel = item.category || "Tâm sự";
      leftSpan.textContent = `#${item.id} • [${catLabel}] • ${new Date(item.created_at * 1000).toLocaleString("vi-VN")}`;

      const badge = document.createElement("span");
      const statusMap = {
        pending: ["Đang chờ duyệt", "badge-pending"],
        approved: ["Đã duyệt", "badge-approved"],
        rejected: ["Đã từ chối", "badge-rejected"]
      };
      const [label, cls] = statusMap[item.status] || ["Không rõ", ""];
      badge.textContent = label;
      badge.className = `badge ${cls}`;

      meta.appendChild(leftSpan);
      meta.appendChild(badge);

      const titleH3 = document.createElement("h3");
      titleH3.style.marginBottom = "6px";
      titleH3.style.fontSize = "1.05rem";
      titleH3.textContent = item.title || "Tâm sự ẩn danh";

      const contentP = document.createElement("p");
      contentP.className = "confession-text";
      contentP.textContent = item.content;

      const actions = document.createElement("div");
      actions.className = "admin-actions";

      const approveBtn = document.createElement("button");
      approveBtn.type = "button";
      approveBtn.textContent = "Duyệt đăng";
      approveBtn.disabled = item.status === "approved";
      approveBtn.addEventListener("click", () => updateConfessionStatus(item.id, "approved"));

      const rejectBtn = document.createElement("button");
      rejectBtn.type = "button";
      rejectBtn.className = "btn-secondary";
      rejectBtn.textContent = "Từ chối";
      rejectBtn.disabled = item.status === "rejected";
      rejectBtn.addEventListener("click", () => updateConfessionStatus(item.id, "rejected"));

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "btn-danger";
      deleteBtn.textContent = "Xoá vĩnh viễn";
      deleteBtn.addEventListener("click", () => deleteConfession(item.id));

      actions.appendChild(approveBtn);
      actions.appendChild(rejectBtn);
      actions.appendChild(deleteBtn);

      card.appendChild(meta);
      card.appendChild(titleH3);
      card.appendChild(contentP);
      card.appendChild(actions);
      listEl.appendChild(card);
    });
  }

  adminPage = data.page;
  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  document.getElementById("admin-page-info").textContent = `Trang ${adminPage} / ${totalPages} (Tổng: ${data.total})`;
  document.getElementById("admin-prev-btn").disabled = adminPage <= 1;
  document.getElementById("admin-next-btn").disabled = adminPage >= totalPages;
}

async function updateConfessionStatus(id, newStatus) {
  const res = await fetch(`/api/admin/confessions/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
    credentials: "same-origin",
    body: JSON.stringify({ status: newStatus })
  });
  const data = await res.json();
  if (res.ok) {
    showMsg(globalFeedback, data.message, "success");
    loadAdminConfessions(adminPage);
  } else {
    showMsg(globalFeedback, data.detail || "Lỗi cập nhật.", "error");
  }
}

async function deleteConfession(id) {
  if (!window.confirm(`Bạn có chắc chắn muốn xoá vĩnh viễn Confession #${id}?`)) return;
  const res = await fetch(`/api/admin/confessions/${id}`, {
    method: "DELETE",
    headers: { "X-CSRF-Token": csrfToken },
    credentials: "same-origin"
  });
  const data = await res.json();
  if (res.ok) {
    showMsg(globalFeedback, data.message, "success");
    loadAdminConfessions(adminPage);
  } else {
    showMsg(globalFeedback, data.detail || "Lỗi xoá.", "error");
  }
}

// TAB 2: CẤP QUYỀN & QUẢN LÝ ADMIN (CHỈ MÌNH BẠN CÓ QUYỀN)
document.getElementById("create-admin-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("new-admin-username").value.trim();
  const password = document.getElementById("new-admin-password").value;

  const res = await fetch("/api/admin/users", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
    credentials: "same-origin",
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (res.ok) {
    showMsg(globalFeedback, data.message, "success");
    document.getElementById("new-admin-username").value = "";
    document.getElementById("new-admin-password").value = "";
    loadUsersList();
  } else {
    showMsg(globalFeedback, data.detail || "Không thể cấp quyền Admin.", "error");
  }
});

async function loadUsersList() {
  const res = await fetch("/api/admin/users", { credentials: "same-origin" });
  if (!res.ok) return;
  const data = await res.json();

  const usersList = document.getElementById("users-list");
  usersList.replaceChildren();

  data.users.forEach((u) => {
    const item = document.createElement("div");
    item.className = "confession-item";

    const meta = document.createElement("div");
    meta.className = "confession-meta";

    const title = document.createElement("span");
    const roleName = u.role === "owner" ? "Quản trị tối cao (Bạn - Chủ dự án)" : "Admin duyệt bài (Giới hạn)";
    title.textContent = `${u.username} • ${roleName}`;

    const statusBadge = document.createElement("span");
    if (u.is_locked) {
      statusBadge.textContent = "Đang bị khoá";
      statusBadge.className = "badge badge-rejected";
    } else {
      statusBadge.textContent = "Đang hoạt động";
      statusBadge.className = "badge badge-approved";
    }

    meta.appendChild(title);
    meta.appendChild(statusBadge);
    item.appendChild(meta);

    if (u.role !== "owner") {
      const actions = document.createElement("div");
      actions.className = "admin-actions";

      const resetPwBtn = document.createElement("button");
      resetPwBtn.type = "button";
      resetPwBtn.className = "btn-secondary";
      resetPwBtn.textContent = "Đổi mật khẩu";
      resetPwBtn.addEventListener("click", () => resetSubAdminPassword(u.id, u.username));

      const lockBtn = document.createElement("button");
      lockBtn.type = "button";
      lockBtn.className = "btn-secondary";
      lockBtn.textContent = u.is_locked ? "Mở khoá quyền" : "Tạm khoá quyền";
      lockBtn.addEventListener("click", () => toggleLockUser(u.id, !u.is_locked));

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "btn-danger";
      delBtn.textContent = "Thu hồi quyền (Xoá)";
      delBtn.addEventListener("click", () => deleteUser(u.id, u.username));

      actions.appendChild(resetPwBtn);
      actions.appendChild(lockBtn);
      actions.appendChild(delBtn);
      item.appendChild(actions);
    }

    usersList.appendChild(item);
  });
}

async function resetSubAdminPassword(userId, username) {
  const newPassword = window.prompt(`Nhập mật khẩu mới (tối thiểu 6 ký tự) cho Admin "${username}":`);
  if (!newPassword) return;
  if (newPassword.length < 6) {
    window.alert("Mật khẩu phải có ít nhất 6 ký tự.");
    return;
  }

  const res = await fetch(`/api/admin/users/${userId}/password`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
    credentials: "same-origin",
    body: JSON.stringify({ new_password: newPassword })
  });
  const data = await res.json();
  if (res.ok) {
    showMsg(globalFeedback, data.message, "success");
  } else {
    showMsg(globalFeedback, data.detail || "Không thể đổi mật khẩu.", "error");
  }
}

async function toggleLockUser(userId, lockState) {
  const res = await fetch(`/api/admin/users/${userId}/lock`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
    credentials: "same-origin",
    body: JSON.stringify({ is_locked: lockState })
  });
  const data = await res.json();
  if (res.ok) {
    showMsg(globalFeedback, data.message, "success");
    loadUsersList();
  } else {
    showMsg(globalFeedback, data.detail || "Lỗi thao tác.", "error");
  }
}

async function deleteUser(userId, username) {
  if (!window.confirm(`Thu hồi quyền và xoá vĩnh viễn tài khoản Admin "${username}"?`)) return;
  const res = await fetch(`/api/admin/users/${userId}`, {
    method: "DELETE",
    headers: { "X-CSRF-Token": csrfToken },
    credentials: "same-origin"
  });
  const data = await res.json();
  if (res.ok) {
    showMsg(globalFeedback, data.message, "success");
    loadUsersList();
  } else {
    showMsg(globalFeedback, data.detail || "Không thể xoá tài khoản.", "error");
  }
}

// TAB 3: NHẬT KÝ HOẠT ĐỘNG
async function loadActivityLogs(page = 1) {
  const res = await fetch(`/api/admin/logs?page=${page}&page_size=20`, { credentials: "same-origin" });
  if (!res.ok) return;
  const data = await res.json();

  const logsList = document.getElementById("logs-list");
  logsList.replaceChildren();

  data.items.forEach((log) => {
    const item = document.createElement("div");
    item.className = "confession-item";

    const meta = document.createElement("div");
    meta.className = "confession-meta";
    const timeStr = new Date(log.created_at * 1000).toLocaleString("vi-VN");
    meta.textContent = `[${timeStr}] ${log.actor_username} (${log.actor_role}) • ${log.action} • IP: ${log.ip_address}`;

    const detailP = document.createElement("p");
    detailP.className = "confession-text";
    detailP.textContent = log.details;

    item.appendChild(meta);
    item.appendChild(detailP);
    logsList.appendChild(item);
  });

  logsPage = data.page;
  const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
  document.getElementById("logs-page-info").textContent = `Trang ${logsPage} / ${totalPages} (Tổng: ${data.total} sự kiện)`;
  document.getElementById("logs-prev-btn").disabled = logsPage <= 1;
  document.getElementById("logs-next-btn").disabled = logsPage >= totalPages;
}

document.getElementById("filter-btn").addEventListener("click", () => loadAdminConfessions(1));
document.getElementById("admin-prev-btn").addEventListener("click", () => {
  if (adminPage > 1) loadAdminConfessions(adminPage - 1);
});
document.getElementById("admin-next-btn").addEventListener("click", () => loadAdminConfessions(adminPage + 1));

document.getElementById("logs-prev-btn").addEventListener("click", () => {
  if (logsPage > 1) loadActivityLogs(logsPage - 1);
});
document.getElementById("logs-next-btn").addEventListener("click", () => loadActivityLogs(logsPage + 1));

logoutBtn.addEventListener("click", async () => {
  await fetch("/api/admin/logout", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    credentials: "same-origin"
  });
  logoutBtn.classList.add("hidden");
  currentUserBadge.classList.add("hidden");
  dashboardSection.classList.add("hidden");
  loginSection.classList.remove("hidden");
});

window.addEventListener("DOMContentLoaded", async () => {
  await initCsrf();
  const res = await fetch("/api/admin/me", { credentials: "same-origin" });
  if (res.ok) {
    const data = await res.json();
    enterDashboard(data.username, data.role);
  } else {
    loginSection.classList.remove("hidden");
  }
});