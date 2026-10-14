/**
 * CONFESS - FRONTEND APPLICATION LOGIC (app.js)
 * Kết nối giao diện Soft Pastel UI với Backend FastAPI & CSRF Security.
 */

const API_ENDPOINTS = {
  CSRF: '/api/csrf',
  SEND_OTP: '/api/auth/send-otp',
  VERIFY_OTP: '/api/auth/verify-otp',
  CONFESSIONS: '/api/confessions',
  MY_CONFESSIONS: '/api/my-confessions',
  CONFESSION_DETAIL: (id) => `/api/confessions/${encodeURIComponent(id)}`,
  LIKE_CONFESSION: (id) => `/api/confessions/${encodeURIComponent(id)}/like`,
  COMMENTS: (id) => `/api/confessions/${encodeURIComponent(id)}/comments`,
};

const STORAGE_KEYS = {
  DRAFT: 'confess_pastel_draft_v1',
  BOOKMARKS: 'confess_saved_ids_v1',
  AUTH_TOKEN: 'confess_session_token',
};

const appState = {
  csrfToken: '',
  currentView: 'home',
  currentCategory: 'all',
  currentSort: 'newest',
  searchQuery: '',
  verifiedSessionToken: sessionStorage.getItem(STORAGE_KEYS.AUTH_TOKEN) || null,
  pendingEmail: '',
  otpCountdown: null,
  confessions: [],
  myConfessions: [],
  activeConfessionId: null,
  savedIds: JSON.parse(localStorage.getItem(STORAGE_KEYS.BOOKMARKS) || '[]'),
};

/* ==================== KHỞI TẠO CSRF & HEADER DÙNG CHUNG ==================== */
async function initCsrf() {
  try {
    const res = await fetch(API_ENDPOINTS.CSRF, { credentials: 'same-origin' });
    if (res.ok) {
      const data = await res.json();
      appState.csrfToken = data.csrf_token || '';
    }
  } catch (err) {
    console.warn('Không thể khởi tạo CSRF token:', err);
  }
}

function buildHeaders(includeJson = true) {
  const headers = {};
  if (includeJson) headers['Content-Type'] = 'application/json';
  if (appState.csrfToken) headers['X-CSRF-Token'] = appState.csrfToken;
  if (appState.verifiedSessionToken) {
    headers['Authorization'] = `Bearer ${appState.verifiedSessionToken}`;
  }
  return headers;
}

/* ==================== HÀM TIỆN ÍCH AN TOÀN (ANTI-XSS & THUMBNAIL) ==================== */
function escapeHTML(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function toTimestampMs(dateInput) {
  if (!dateInput) return Date.now();
  if (typeof dateInput === 'number') {
    return dateInput < 1e12 ? dateInput * 1000 : dateInput;
  }
  if (/^\d+$/.test(String(dateInput))) {
    const num = Number(dateInput);
    return num < 1e12 ? num * 1000 : num;
  }
  const parsed = new Date(dateInput).getTime();
  return isNaN(parsed) ? Date.now() : parsed;
}

function formatRelativeTime(dateInput) {
  if (!dateInput) return 'Vừa xong';
  const timeMs = toTimestampMs(dateInput);
  const diffSec = Math.max(1, Math.floor((Date.now() - timeMs) / 1000));
  if (diffSec < 60) return 'Vừa xong';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)} phút trước`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} giờ trước`;
  return `${Math.floor(diffSec / 86400)} ngày trước`;
}

function getPastelThumbnailSVG(category = 'Tâm sự') {
  const palettes = {
    'Tâm sự': ['#CFD9FF', '#F6D9E8', '#5E72C6'],
    'Tình yêu': ['#FFD8E6', '#FFF0F5', '#D96B90'],
    'Học tập': ['#D4EAFF', '#EFEAFF', '#4A80C8'],
    'Cuộc sống': ['#D6F5E8', '#FFF4DE', '#3B9B74'],
    'Khác': ['#E5DEFF', '#FDE8F0', '#7B68C8'],
  };
  const [c1, c2, stroke] = palettes[category] || palettes['Tâm sự'];
  return `
    <svg viewBox="0 0 100 100" width="100%" height="100%" aria-hidden="true">
      <defs>
        <linearGradient id="g-${escapeHTML(category)}" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="${c1}"/>
          <stop offset="100%" stop-color="${c2}"/>
        </linearGradient>
      </defs>
      <rect width="100" height="100" fill="url(#g-${escapeHTML(category)})"/>
      <circle cx="74" cy="26" r="11" fill="#FFF9EC" opacity="0.85"/>
      <path d="M16 74c10-9 26-7 34 2 9-6 22-4 28 6H10c2-5 4-8 6-8z" fill="#FFFFFF" opacity="0.75"/>
      <text x="50" y="54" text-anchor="middle" fill="${stroke}" font-size="18" font-family="Caveat, cursive">♡</text>
    </svg>
  `;
}

function showToast(message) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 3400);
}

/* ==================== ĐIỀU HƯỚNG GIỮA 4 MÀN HÌNH ==================== */
function switchView(viewName) {
  appState.currentView = viewName;
  document.querySelectorAll('.view-section').forEach((sec) => sec.classList.remove('active'));
  const target = document.getElementById(`view-${viewName}`);
  if (target) target.classList.add('active');

  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.nav === viewName);
  });

  const quoteEl = document.getElementById('sidebar-quote');
  if (quoteEl) {
    quoteEl.innerHTML =
      viewName === 'submit'
        ? 'Viết những điều<br/>bạn chưa từng nói!<br/>♡'
        : 'Những điều bạn<br/>không thể nói...<br/>Ở đây, bạn có thể. ♡';
  }

  document.getElementById('sidebar')?.classList.remove('open');

  if (viewName === 'feed') loadPublicConfessions();
  if (viewName === 'my-posts') loadMyConfessions();
  if (viewName === 'submit') initSubmitFlow();
}

/* ==================== MÀN HÌNH 2: BẢNG TIN CONFESSION ==================== */
async function loadPublicConfessions() {
  const loadingEl = document.getElementById('feed-loading');
  const listEl = document.getElementById('confession-list');
  loadingEl.classList.remove('hidden');
  listEl.innerHTML = '';

  try {
    const params = new URLSearchParams({
      category: appState.currentCategory === 'all' ? '' : appState.currentCategory,
      sort: appState.currentSort,
      q: appState.searchQuery,
    });
    const res = await fetch(`${API_ENDPOINTS.CONFESSIONS}?${params.toString()}`, {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });
    if (res.ok) {
      const data = await res.json();
      const rawList = Array.isArray(data) ? data : data.items || data.confessions || [];
      appState.confessions = rawList.filter((item) => !item.status || item.status === 'approved');
    }
  } catch (err) {
    console.warn('Không thể kết nối API bảng tin:', err);
  } finally {
    loadingEl.classList.add('hidden');
    renderFeedList();
    renderFeedSidebar();
  }
}

function renderFeedList() {
  const listEl = document.getElementById('confession-list');
  const emptyEl = document.getElementById('feed-empty');

  let filtered = [...appState.confessions];
  if (appState.currentCategory !== 'all') {
    filtered = filtered.filter((c) => (c.category || 'Tâm sự') === appState.currentCategory);
  }
  if (appState.searchQuery.trim()) {
    const q = appState.searchQuery.toLowerCase();
    filtered = filtered.filter(
      (c) =>
        (c.title || '').toLowerCase().includes(q) ||
        (c.content || '').toLowerCase().includes(q)
    );
  }
  if (appState.currentSort === 'popular') {
    filtered.sort((a, b) => (b.likes_count || b.likes || 0) - (a.likes_count || a.likes || 0));
  } else {
    filtered.sort((a, b) => toTimestampMs(b.created_at) - toTimestampMs(a.created_at));
  }

  if (filtered.length === 0) {
    listEl.innerHTML = '';
    emptyEl.classList.remove('hidden');
    return;
  }

  emptyEl.classList.add('hidden');
  listEl.innerHTML = filtered
    .map((item) => {
      const cat = escapeHTML(item.category || 'Tâm sự');
      const title = escapeHTML(item.title || 'Tâm sự ẩn danh');
      const excerpt = escapeHTML(item.content || '');
      const timeStr = formatRelativeTime(item.created_at);
      const likes = Number(item.likes_count ?? item.likes ?? 0);
      const comments = Number(item.comments_count ?? item.comments?.length ?? 0);
      const isSaved = appState.savedIds.includes(String(item.id));

      return `
        <article class="confession-card" data-id="${escapeHTML(item.id)}">
          <div class="card-thumb">${getPastelThumbnailSVG(item.category)}</div>
          <div class="card-body">
            <div class="card-top-meta">
              <span class="category-badge" data-cat="${cat}">${cat}</span>
              <span aria-hidden="true">•••</span>
            </div>
            <h3 class="card-title">${title}</h3>
            <p class="card-excerpt">${excerpt}</p>
            <div class="card-footer">
              <span>${timeStr} • Ẩn danh</span>
              <div class="card-interactions">
                <button type="button" class="interaction-btn like-btn ${item.liked ? 'liked' : ''}" data-like-id="${escapeHTML(item.id)}">
                  ♥ <span>${likes}</span>
                </button>
                <span class="interaction-btn">💬 ${comments}</span>
                <button type="button" class="interaction-btn bookmark-btn" data-save-id="${escapeHTML(item.id)}" title="Lưu bài viết">
                  ${isSaved ? '🔖' : '☆'}
                </button>
              </div>
            </div>
          </div>
        </article>
      `;
    })
    .join('');
}

function renderFeedSidebar() {
  const categories = ['Tất cả', 'Tình yêu', 'Học tập', 'Cuộc sống', 'Tâm sự', 'Khác'];
  const statsEl = document.getElementById('sidebar-category-stats');
  if (statsEl) {
    statsEl.innerHTML = categories
      .map((cat) => {
        const count =
          cat === 'Tất cả'
            ? appState.confessions.length
            : appState.confessions.filter((c) => (c.category || 'Tâm sự') === cat).length;
        return `
          <li class="category-stats-item" data-side-cat="${cat === 'Tất cả' ? 'all' : cat}">
            <span>${escapeHTML(cat)}</span>
            <strong>${count}</strong>
          </li>
        `;
      })
      .join('');
  }

  const recentEl = document.getElementById('sidebar-recent-posts');
  if (recentEl) {
    const recent = appState.confessions.slice(0, 3);
    recentEl.innerHTML = recent
      .map(
        (item) => `
        <div class="mini-post-item" data-open-id="${escapeHTML(item.id)}">
          <div class="mini-post-thumb">${getPastelThumbnailSVG(item.category)}</div>
          <div class="mini-post-info">
            <h4>${escapeHTML(item.title || 'Tâm sự ẩn danh')}</h4>
            <span>${formatRelativeTime(item.created_at)}</span>
          </div>
        </div>
      `
      )
      .join('');
  }
}

/* ==================== THẢ TIM & LƯU BÀI VIẾT ==================== */
async function handleToggleLike(confessionId, btnEl) {
  try {
    const res = await fetch(API_ENDPOINTS.LIKE_CONFESSION(confessionId), {
      method: 'POST',
      credentials: 'same-origin',
      headers: buildHeaders(false),
    });
    if (!res.ok) return;
    const data = await res.json();

    const target = appState.confessions.find((c) => String(c.id) === String(confessionId));
    if (target) {
      target.likes_count = data.likes_count;
      target.liked = data.liked;
    }
    if (btnEl) {
      btnEl.classList.toggle('liked', data.liked);
      const countSpan = btnEl.querySelector('span');
      if (countSpan) countSpan.textContent = String(data.likes_count);
    }
  } catch (err) {
    console.warn('Không thể thả tim lúc này:', err);
  }
}

function handleToggleBookmark(confessionId) {
  const idStr = String(confessionId);
  const idx = appState.savedIds.indexOf(idStr);
  if (idx >= 0) {
    appState.savedIds.splice(idx, 1);
    showToast('Đã bỏ lưu bài viết.');
  } else {
    appState.savedIds.push(idStr);
    showToast('Đã lưu bài viết vào bộ nhớ trình duyệt ♡');
  }
  localStorage.setItem(STORAGE_KEYS.BOOKMARKS, JSON.stringify(appState.savedIds));
  if (appState.currentView === 'feed') renderFeedList();
}

/* ==================== MÀN HÌNH 3: QUY TRÌNH 3 BƯỚC GỬI CONFESSION ==================== */
function setSubmitStep(stepNumber) {
  [1, 2, 3].forEach((n) => {
    const panel = document.getElementById(`step-${n}-panel`);
    const indicator = document.querySelector(`[data-step-indicator="${n}"]`);
    if (panel) panel.classList.toggle('hidden', n !== stepNumber);
    if (indicator) {
      indicator.classList.toggle('active', n === stepNumber);
      indicator.classList.toggle('completed', n < stepNumber);
    }
  });
}

function initSubmitFlow() {
  document.getElementById('post-submit-status-box')?.classList.add('hidden');
  document.getElementById('confession-compose-form')?.classList.remove('hidden');

  const editingId = document.getElementById('editing-confession-id')?.value;
  if (!editingId) {
    document.getElementById('compose-form-heading').textContent = 'Viết tâm sự của bạn';
    restoreDraftFromLocal();
  }

  if (appState.verifiedSessionToken) {
    setSubmitStep(3);
  } else {
    setSubmitStep(1);
  }
}

function startOtpTimer() {
  clearInterval(appState.otpCountdown);
  let remaining = 60;
  const resendBtn = document.getElementById('resend-otp-btn');
  resendBtn.disabled = true;
  resendBtn.innerHTML = 'Gửi lại mã (<span id="otp-timer">60</span>s)';

  appState.otpCountdown = setInterval(() => {
    remaining -= 1;
    const timerSpan = document.getElementById('otp-timer');
    if (timerSpan) timerSpan.textContent = String(remaining);
    if (remaining <= 0) {
      clearInterval(appState.otpCountdown);
      resendBtn.disabled = false;
      resendBtn.textContent = 'Gửi lại mã xác nhận';
    }
  }, 1000);
}

function saveDraftToLocal() {
  const editingId = document.getElementById('editing-confession-id')?.value;
  if (editingId) return; // Không ghi đè bản nháp khi đang sửa bài đã gửi
  const draft = {
    category: document.getElementById('confession-category')?.value || 'Tâm sự',
    title: document.getElementById('confession-title')?.value || '',
    content: document.getElementById('confession-content')?.value || '',
    updatedAt: new Date().toISOString(),
  };
  localStorage.setItem(STORAGE_KEYS.DRAFT, JSON.stringify(draft));
  const badge = document.getElementById('draft-status-badge');
  if (badge) badge.textContent = 'Đã tự động lưu nháp ✓';
}

function restoreDraftFromLocal() {
  const raw = localStorage.getItem(STORAGE_KEYS.DRAFT);
  if (!raw) return;
  try {
    const draft = JSON.parse(raw);
    if (draft.category) document.getElementById('confession-category').value = draft.category;
    if (draft.title) document.getElementById('confession-title').value = draft.title;
    if (draft.content) {
      const contentEl = document.getElementById('confession-content');
      contentEl.value = draft.content;
      updateCharCounter();
    }
  } catch (e) {
    console.warn('Không thể đọc bản nháp:', e);
  }
}

function updateCharCounter() {
  const contentEl = document.getElementById('confession-content');
  const counterEl = document.getElementById('char-counter');
  if (!contentEl || !counterEl) return;
  const len = contentEl.value.length;
  counterEl.textContent = `${len} / 3000 ký tự`;
}

/* ==================== MÀN HÌNH 4: CHI TIẾT BÀI VIẾT & BÌNH LUẬN ==================== */
async function openConfessionDetail(confessionId) {
  appState.activeConfessionId = confessionId;
  switchView('detail');

  let item = appState.confessions.find((c) => String(c.id) === String(confessionId));
  try {
    const res = await fetch(API_ENDPOINTS.CONFESSION_DETAIL(confessionId), {
      credentials: 'same-origin',
      headers: buildHeaders(false),
    });
    if (res.ok) item = await res.json();
  } catch (e) {
    console.warn('Sử dụng dữ liệu bộ nhớ đệm cho chi tiết confession:', e);
  }

  if (!item) return;

  const articleEl = document.getElementById('detail-article-card');
  const cat = escapeHTML(item.category || 'Tâm sự');
  const likes = Number(item.likes_count ?? item.likes ?? 0);
  const commentsCount = Number(item.comments_count ?? item.comments?.length ?? 0);

  articleEl.innerHTML = `
    <div class="detail-header">
      <div>
        <span class="category-badge" data-cat="${cat}">${cat}</span>
        <h1 class="detail-title">${escapeHTML(item.title || 'Tâm sự ẩn danh')}</h1>
        <div class="detail-meta">${formatRelativeTime(item.created_at)} • Ẩn danh</div>
      </div>
      <div class="detail-thumb">${getPastelThumbnailSVG(item.category)}</div>
    </div>
    <div class="detail-content">${escapeHTML(item.content || '')}</div>
    <div class="detail-reactions-bar">
      <div class="card-interactions">
        <button type="button" class="interaction-btn like-btn ${item.liked ? 'liked' : ''}" data-like-id="${escapeHTML(item.id)}">
          ♥ <span>${likes}</span>
        </button>
        <span class="interaction-btn">💬 ${commentsCount}</span>
        <button type="button" class="interaction-btn bookmark-btn" data-save-id="${escapeHTML(item.id)}">
          🔖 Lưu bài
        </button>
      </div>
      <span>•••</span>
    </div>
  `;

  const statusBanner = document.getElementById('detail-status-banner');
  if (item.status === 'pending') {
    statusBanner.className = 'status-pill pending';
    statusBanner.textContent = '⏳ Bài viết đang chờ kiểm duyệt.';
  } else {
    statusBanner.className = 'status-pill approved';
    statusBanner.textContent = '✓ Bài viết này đã được duyệt và công khai.';
  }

  const ownerGroup = document.getElementById('owner-actions-group');
  ownerGroup.classList.toggle('hidden', !item.is_owner && !item.can_edit);

  const editBtn = document.getElementById('detail-edit-btn');
  if (editBtn) {
    editBtn.onclick = () => {
      document.getElementById('editing-confession-id').value = String(item.id);
      document.getElementById('confession-category').value = item.category || 'Tâm sự';
      document.getElementById('confession-title').value = item.title || '';
      document.getElementById('confession-content').value = item.content || '';
      document.getElementById('compose-form-heading').textContent = `Chỉnh sửa Confession #${item.id}`;
      updateCharCounter();
      switchView('submit');
    };
  }

  const deleteBtn = document.getElementById('detail-delete-btn');
  if (deleteBtn) {
    deleteBtn.onclick = async () => {
      if (!window.confirm('Bạn có chắc chắn muốn xoá bài viết này?')) return;
      const res = await fetch(API_ENDPOINTS.CONFESSION_DETAIL(item.id), {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: buildHeaders(false),
      });
      if (res.ok) {
        showToast('Đã xoá bài viết thành công.');
        switchView('my-posts');
      } else {
        showToast('Không thể xoá bài viết lúc này.');
      }
    };
  }

  renderComments(item.comments || []);
  renderRelatedConfessions(item);
}

function renderComments(comments) {
  const listEl = document.getElementById('comments-list');
  if (!comments || comments.length === 0) {
    listEl.innerHTML = `<p class="step-desc">Chưa có bình luận nào. Hãy gửi lời động viên đầu tiên nhé! ♡</p>`;
    return;
  }

  listEl.innerHTML = comments
    .map(
      (c) => `
      <div class="comment-item">
        <div class="comment-avatar">♡</div>
        <div class="comment-body">
          <div class="comment-author">${escapeHTML(c.author_alias || 'Một người bạn ẩn danh')}</div>
          <div class="comment-text">${escapeHTML(c.content || '')}</div>
          <div class="comment-meta">
            <span>${formatRelativeTime(c.created_at)}</span>
            <span>♥ ${Number(c.likes || 0)}</span>
          </div>
        </div>
      </div>
    `
    )
    .join('');
}

function renderRelatedConfessions(currentItem) {
  const container = document.getElementById('related-confessions-list');
  const related = appState.confessions
    .filter((c) => String(c.id) !== String(currentItem.id))
    .slice(0, 3);

  container.innerHTML = related
    .map(
      (item) => `
      <div class="mini-post-item" data-open-id="${escapeHTML(item.id)}">
        <div class="mini-post-thumb">${getPastelThumbnailSVG(item.category)}</div>
        <div class="mini-post-info">
          <h4>${escapeHTML(item.title || 'Tâm sự ẩn danh')}</h4>
          <span>${escapeHTML(item.category || 'Tâm sự')} • ${formatRelativeTime(item.created_at)}</span>
        </div>
      </div>
    `
    )
    .join('');
}

/* ==================== BÀI VIẾT CỦA TÔI ==================== */
async function loadMyConfessions() {
  const container = document.getElementById('my-posts-list');
  container.innerHTML = '';

  try {
    const res = await fetch(API_ENDPOINTS.MY_CONFESSIONS, {
      credentials: 'same-origin',
      headers: buildHeaders(false),
    });
    if (res.ok) {
      const data = await res.json();
      appState.myConfessions = Array.isArray(data) ? data : data.items || [];
    }
  } catch (err) {
    console.warn('Không thể tải danh sách bài viết cá nhân:', err);
  }

  const localDraftRaw = localStorage.getItem(STORAGE_KEYS.DRAFT);
  let html = '';

  if (localDraftRaw) {
    try {
      const draft = JSON.parse(localDraftRaw);
      if (draft.title || draft.content) {
        html += `
          <article class="confession-card" id="resume-local-draft-card">
            <div class="card-thumb">${getPastelThumbnailSVG(draft.category)}</div>
            <div class="card-body">
              <div class="card-top-meta">
                <span class="category-badge">📝 Bản nháp trên thiết bị</span>
              </div>
              <h3 class="card-title">${escapeHTML(draft.title || '(Chưa có tiêu đề)')}</h3>
              <p class="card-excerpt">${escapeHTML(draft.content || '')}</p>
              <div class="card-footer">
                <span>Nhấn để tiếp tục chỉnh sửa và gửi</span>
              </div>
            </div>
          </article>
        `;
      }
    } catch (e) {}
  }

  html += appState.myConfessions
    .map(
      (item) => `
      <article class="confession-card" data-id="${escapeHTML(item.id)}">
        <div class="card-thumb">${getPastelThumbnailSVG(item.category)}</div>
        <div class="card-body">
          <div class="card-top-meta">
            <span class="category-badge">${escapeHTML(item.category || 'Tâm sự')}</span>
            <span>${item.status === 'approved' ? '✓ Đã duyệt' : item.status === 'rejected' ? '✕ Đã từ chối' : '⏳ Đang chờ duyệt'}</span>
          </div>
          <h3 class="card-title">${escapeHTML(item.title || 'Tâm sự ẩn danh')}</h3>
          <p class="card-excerpt">${escapeHTML(item.content)}</p>
        </div>
      </article>
    `
    )
    .join('');

  container.innerHTML =
    html ||
    `<div class="state-box"><p>Bạn chưa có bài viết hoặc bản nháp nào.</p></div>`;
}

/* ==================== KHỞI TẠO SỰ KIỆN DOM ==================== */
document.addEventListener('DOMContentLoaded', async () => {
  await initCsrf();
  loadPublicConfessions();

  document.body.addEventListener('click', (e) => {
    const likeBtn = e.target.closest('[data-like-id]');
    if (likeBtn) {
      e.stopPropagation();
      handleToggleLike(likeBtn.dataset.likeId, likeBtn);
      return;
    }

    const saveBtn = e.target.closest('[data-save-id]');
    if (saveBtn) {
      e.stopPropagation();
      handleToggleBookmark(saveBtn.dataset.saveId);
      return;
    }

    const draftCard = e.target.closest('#resume-local-draft-card');
    if (draftCard) {
      document.getElementById('editing-confession-id').value = '';
      switchView('submit');
      return;
    }

    const navTrigger = e.target.closest('[data-nav]');
    if (navTrigger) {
      e.preventDefault();
      if (navTrigger.dataset.nav === 'submit') {
        document.getElementById('editing-confession-id').value = '';
      }
      switchView(navTrigger.dataset.nav);
      return;
    }

    const card = e.target.closest('.confession-card[data-id]');
    if (card && !e.target.closest('button')) {
      openConfessionDetail(card.dataset.id);
      return;
    }

    const miniItem = e.target.closest('[data-open-id]');
    if (miniItem) {
      openConfessionDetail(miniItem.dataset.openId);
      return;
    }

    const sideCat = e.target.closest('[data-side-cat]');
    if (sideCat) {
      appState.currentCategory = sideCat.dataset.sideCat;
      document.querySelectorAll('#category-pills .pill-btn').forEach((b) => {
        b.classList.toggle('active', b.dataset.category === appState.currentCategory);
      });
      renderFeedList();
    }
  });

  document.getElementById('mobile-menu-btn')?.addEventListener('click', () => {
    document.getElementById('sidebar')?.classList.toggle('open');
  });

  document.getElementById('category-pills')?.addEventListener('click', (e) => {
    const btn = e.target.closest('.pill-btn');
    if (!btn) return;
    document.querySelectorAll('#category-pills .pill-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    appState.currentCategory = btn.dataset.category;
    renderFeedList();
  });

  document.getElementById('feed-sort-select')?.addEventListener('change', (e) => {
    appState.currentSort = e.target.value;
    renderFeedList();
  });

  document.getElementById('global-search-form')?.addEventListener('submit', (e) => {
    e.preventDefault();
    appState.searchQuery = document.getElementById('global-search-input').value;
    if (appState.currentView !== 'feed') switchView('feed');
    else renderFeedList();
  });

  // Bước 1: Gửi mã OTP qua Email
  async function requestOtpForEmail(email) {
    const res = await fetch(API_ENDPOINTS.SEND_OTP, {
      method: 'POST',
      credentials: 'same-origin',
      headers: buildHeaders(true),
      body: JSON.stringify({ email }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      const msg = typeof errData.detail === 'object' ? errData.detail.message : errData.detail;
      throw new Error(msg || errData.message || 'Không thể gửi mã xác nhận.');
    }
  }

  document.getElementById('email-step-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const emailInput = document.getElementById('verify-email-input');
    const errorEl = document.getElementById('email-error-msg');
    const email = emailInput.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(email)) {
      errorEl.textContent = 'Vui lòng nhập địa chỉ email hợp lệ.';
      errorEl.classList.remove('hidden');
      return;
    }
    errorEl.classList.add('hidden');

    const btn = document.getElementById('send-otp-btn');
    btn.disabled = true;
    btn.textContent = 'Đang gửi mã...';

    try {
      await requestOtpForEmail(email);
      appState.pendingEmail = email;
      setSubmitStep(2);
      startOtpTimer();
      showToast('Mã xác nhận đã được gửi tới email của bạn.');
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Gửi mã xác nhận';
    }
  });

  document.getElementById('resend-otp-btn')?.addEventListener('click', async () => {
    if (!appState.pendingEmail) return;
    try {
      await requestOtpForEmail(appState.pendingEmail);
      startOtpTimer();
      showToast('Đã gửi lại mã xác nhận mới!');
    } catch (err) {
      showToast(err.message);
    }
  });

  const otpBoxes = Array.from(document.querySelectorAll('.otp-box'));
  otpBoxes.forEach((box, idx) => {
    box.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '');
      if (e.target.value && idx < otpBoxes.length - 1) {
        otpBoxes[idx + 1].focus();
      }
    });
    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !box.value && idx > 0) {
        otpBoxes[idx - 1].focus();
      }
    });
  });

  document.getElementById('back-to-step-1-btn')?.addEventListener('click', () => setSubmitStep(1));

  // Bước 2: Xác minh OTP
  document.getElementById('otp-step-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = otpBoxes.map((b) => b.value).join('');
    const errorEl = document.getElementById('otp-error-msg');

    if (code.length !== 6) {
      errorEl.textContent = 'Vui lòng nhập đầy đủ 6 chữ số xác nhận.';
      errorEl.classList.remove('hidden');
      return;
    }
    errorEl.classList.add('hidden');

    try {
      const res = await fetch(API_ENDPOINTS.VERIFY_OTP, {
        method: 'POST',
        credentials: 'same-origin',
        headers: buildHeaders(true),
        body: JSON.stringify({ email: appState.pendingEmail, otp_code: code, otp: code, code }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || errData.message || 'Mã OTP không chính xác hoặc đã hết hạn.');
      }
      const data = await res.json();
      appState.verifiedSessionToken = data.token || data.access_token || 'verified-session';
      sessionStorage.setItem(STORAGE_KEYS.AUTH_TOKEN, appState.verifiedSessionToken);
      setSubmitStep(3);
      showToast('Xác thực thành công! Hãy viết tâm sự của bạn.');
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
    }
  });

  // Bước 3: Bộ đếm ký tự & tự động lưu nháp
  document.getElementById('confession-content')?.addEventListener('input', () => {
    updateCharCounter();
    saveDraftToLocal();
  });
  document.getElementById('confession-title')?.addEventListener('input', saveDraftToLocal);
  document.getElementById('save-draft-btn')?.addEventListener('click', () => {
    saveDraftToLocal();
    showToast('Đã lưu bản nháp thành công!');
  });

  document.getElementById('preview-confession-btn')?.addEventListener('click', () => {
    const cat = document.getElementById('confession-category').value;
    const title = document.getElementById('confession-title').value || '(Chưa có tiêu đề)';
    const content = document.getElementById('confession-content').value || '(Chưa có nội dung)';
    const modalBody = document.getElementById('preview-modal-body');
    modalBody.innerHTML = `
      <span class="category-badge">${escapeHTML(cat)}</span>
      <h2 class="detail-title">${escapeHTML(title)}</h2>
      <p class="detail-content">${escapeHTML(content)}</p>
    `;
    document.getElementById('preview-modal').classList.remove('hidden');
  });

  document.getElementById('close-preview-modal')?.addEventListener('click', () => {
    document.getElementById('preview-modal').classList.add('hidden');
  });

  // Gửi Confession lên Server
  document.getElementById('confession-compose-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const category = document.getElementById('confession-category').value;
    const title = document.getElementById('confession-title').value.trim() || 'Tâm sự ẩn danh';
    const content = document.getElementById('confession-content').value.trim();
    const editingId = document.getElementById('editing-confession-id').value;
    const errorEl = document.getElementById('compose-error-msg');

    if (content.length < 20 || content.length > 3000) {
      errorEl.textContent = 'Nội dung tâm sự cần từ 20 đến 3000 ký tự.';
      errorEl.classList.remove('hidden');
      return;
    }
    errorEl.classList.add('hidden');

    const url = editingId ? API_ENDPOINTS.CONFESSION_DETAIL(editingId) : API_ENDPOINTS.CONFESSIONS;
    const method = editingId ? 'PUT' : 'POST';

    try {
      const res = await fetch(url, {
        method,
        credentials: 'same-origin',
        headers: buildHeaders(true),
        body: JSON.stringify({ category, title, content }),
      });

      if (!res.ok) {
        if (res.status === 403) {
          sessionStorage.removeItem(STORAGE_KEYS.AUTH_TOKEN);
          appState.verifiedSessionToken = null;
          await initCsrf();
          setSubmitStep(1);
        }
        const errData = await res.json().catch(() => ({}));
        const msg = typeof errData.detail === 'object' ? errData.detail.message : errData.detail;
        throw new Error(msg || errData.message || 'Không thể gửi confession lúc này.');
      }

      localStorage.removeItem(STORAGE_KEYS.DRAFT);
      document.getElementById('editing-confession-id').value = '';
      document.getElementById('confession-compose-form').reset();
      updateCharCounter();
      document.getElementById('confession-compose-form').classList.add('hidden');
      document.getElementById('post-submit-status-box').classList.remove('hidden');
      showToast(editingId ? 'Đã cập nhật confession!' : 'Đã gửi confession! Bài viết đang chờ kiểm duyệt.');
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.classList.remove('hidden');
    }
  });

  document.getElementById('detail-back-btn')?.addEventListener('click', () => switchView('feed'));

  document.getElementById('copy-link-btn')?.addEventListener('click', () => {
    navigator.clipboard?.writeText(window.location.href);
    showToast('Đã sao chép liên kết bài viết!');
  });

  // Gửi bình luận ẩn danh
  document.getElementById('comment-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const inputEl = document.getElementById('comment-input');
    const content = inputEl.value.trim();
    if (!content || !appState.activeConfessionId) return;

    try {
      const res = await fetch(API_ENDPOINTS.COMMENTS(appState.activeConfessionId), {
        method: 'POST',
        credentials: 'same-origin',
        headers: buildHeaders(true),
        body: JSON.stringify({ content }),
      });
      if (res.ok) {
        inputEl.value = '';
        openConfessionDetail(appState.activeConfessionId);
        showToast('Bình luận ẩn danh của bạn đã được gửi ♡');
      } else {
        const errData = await res.json().catch(() => ({}));
        showToast(errData.detail || 'Không thể gửi bình luận lúc này.');
      }
    } catch (err) {
      showToast('Không thể gửi bình luận lúc này.');
    }
  });
});