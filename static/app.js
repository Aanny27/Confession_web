let csrfToken = "";
let currentPage = 1;
let countdownTimer = null;

const confessionForm = document.getElementById("confession-form");
const storyInput = document.getElementById("story-input");
const submitStoryBtn = document.getElementById("submit-story-btn");
const storyFeedback = document.getElementById("story-feedback");
const rateLimitBanner = document.getElementById("rate-limit-banner");
const charCounter = document.getElementById("char-counter");

function showFeedback(element, message, type = "error") {
  element.textContent = message;
  element.className = `field-feedback ${type}`;
}

function hideFeedback(element) {
  element.textContent = "";
  element.className = "field-feedback hidden";
}

function startRateLimitCountdown(seconds, baseMessage) {
  if (countdownTimer) clearInterval(countdownTimer);
  let remaining = seconds;

  const renderTimer = () => {
    const hrs = Math.floor(remaining / 3600);
    const mins = Math.floor((remaining % 3600) / 60);
    const secs = remaining % 60;
    const formatted = `${String(hrs).padStart(2, "0")}:${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
    rateLimitBanner.textContent = `${baseMessage} (Đếm ngược: ${formatted})`;
    rateLimitBanner.className = "field-feedback error";
  };

  renderTimer();
  countdownTimer = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearInterval(countdownTimer);
      hideFeedback(rateLimitBanner);
    } else {
      renderTimer();
    }
  }, 1000);
}

async function fetchCsrfToken() {
  try {
    const res = await fetch("/api/csrf", { credentials: "same-origin" });
    const data = await res.json();
    csrfToken = data.csrf_token;
  } catch (err) {
    console.error("Không thể khởi tạo phiên CSRF", err);
  }
}

storyInput.addEventListener("input", () => {
  const len = storyInput.value.length;
  charCounter.textContent = `${len} / 3000 ký tự (cần tối thiểu 20 ký tự)`;
});

confessionForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideFeedback(storyFeedback);
  const content = storyInput.value.trim();

  if (content.length < 20 || content.length > 3000) {
    showFeedback(
      storyFeedback,
      `Câu chuyện cần có độ dài từ 20 đến 3000 ký tự (hiện tại: ${content.length} ký tự).`,
      "error"
    );
    storyInput.focus();
    return;
  }

  submitStoryBtn.disabled = true;
  submitStoryBtn.textContent = "Đang gửi...";

  try {
    const res = await fetch("/api/confessions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken
      },
      credentials: "same-origin",
      body: JSON.stringify({
        content,
        website_url: document.getElementById("website-url").value
      })
    });
    const data = await res.json();

    if (!res.ok) {
      if (res.status === 429 && data.detail) {
        const msg = typeof data.detail === "object" ? data.detail.message : data.detail;
        const secs = typeof data.detail === "object" ? data.detail.retry_after_seconds : 3600;
        startRateLimitCountdown(secs, msg);
        showFeedback(storyFeedback, msg, "error");
      } else {
        const errMsg = typeof data.detail === "string"
          ? data.detail
          : "Không thể gửi bài viết. Vui lòng kiểm tra lại.";
        showFeedback(storyFeedback, errMsg, "error");
      }
    } else {
      showFeedback(
        storyFeedback,
        `Gửi thành công! ${data.message} (#${data.id}). Hôm nay bạn còn ${data.remaining_today} lượt gửi.`,
        "success"
      );
      storyInput.value = "";
      charCounter.textContent = "0 / 3000 ký tự (cần tối thiểu 20 ký tự)";
    }
  } catch {
    showFeedback(storyFeedback, "Không thể kết nối đến máy chủ. Vui lòng thử lại.", "error");
  } finally {
    submitStoryBtn.disabled = false;
    submitStoryBtn.textContent = "Gửi Confession";
  }
});

async function loadApprovedConfessions(page = 1) {
  const listEl = document.getElementById("confessions-list");
  const prevBtn = document.getElementById("prev-page-btn");
  const nextBtn = document.getElementById("next-page-btn");
  const pageInfo = document.getElementById("page-info");

  try {
    const res = await fetch(`/api/confessions/public?page=${page}&page_size=10`);
    const data = await res.json();

    listEl.replaceChildren();
    if (!data.items || data.items.length === 0) {
      const emptyP = document.createElement("p");
      emptyP.textContent = "Chưa có tâm sự nào được hiển thị.";
      listEl.appendChild(emptyP);
    } else {
      data.items.forEach((item) => {
        const article = document.createElement("article");
        article.className = "confession-item";

        const meta = document.createElement("div");
        meta.className = "confession-meta";
        const dateStr = new Date(item.created_at * 1000).toLocaleString("vi-VN");
        meta.textContent = `#Confession_${item.id} • ${dateStr}`;

        const body = document.createElement("p");
        body.className = "confession-text";
        body.textContent = item.content;

        article.appendChild(meta);
        article.appendChild(body);
        listEl.appendChild(article);
      });
    }

    currentPage = data.page;
    const totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
    pageInfo.textContent = `Trang ${currentPage} / ${totalPages}`;
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;
  } catch {
    listEl.textContent = "Không thể tải danh sách Confession.";
  }
}

document.getElementById("prev-page-btn").addEventListener("click", () => {
  if (currentPage > 1) loadApprovedConfessions(currentPage - 1);
});

document.getElementById("next-page-btn").addEventListener("click", () => {
  loadApprovedConfessions(currentPage + 1);
});

window.addEventListener("DOMContentLoaded", async () => {
  await fetchCsrfToken();
  await loadApprovedConfessions(1);
});