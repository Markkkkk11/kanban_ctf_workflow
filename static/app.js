const $ = (s) => document.querySelector(s);
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
let user,
  comps = [],
  cid = Number(localStorage.getItem("cid")) || 0,
  data,
  page = "board",
  category = "Все",
  ratingEntered = false,
  taskChatTimer = null;
const statuses = {
  free: "Свободны",
  working: "В работе",
  stuck: "Нужна помощь",
  solved: "Решены",
};
const roles = {
  member: "Участник",
  captain: "Капитан",
  admin: "Администратор",
};
const privileged = () => user.role !== "member";
const isAdmin = () => user?.role === "admin";
async function api(path, body) {
  const r = await fetch("/api" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "CTFBoard",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let d;
  try {
    d = await r.json();
  } catch {
    throw Error("Сервер вернул некорректный ответ");
  }
  if (!r.ok) throw Error(d.error || "Ошибка запроса");
  return d;
}
async function waitForFlag(jobId) {
  const deadline = Date.now() + 5 * 60 * 1000;
  while (Date.now() < deadline) {
    const job = await api("/flags/" + jobId);
    if (!["queued", "processing"].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 750));
  }
  throw Error("Проверка флага занимает слишком много времени. Результат появится после обновления карточки.");
}
function toast(s) {
  $("#toast").textContent = s;
  $("#toast").style.display = "block";
  setTimeout(() => ($("#toast").style.display = "none"), 4000);
}
const PASSWORD_MIN_LENGTH = 8;
function clearPasswordError(form) {
  const error = form.querySelector(".password-error");
  if (error) error.textContent = "";
  form.querySelectorAll('[aria-invalid="true"]').forEach((input) => {
    input.removeAttribute("aria-invalid");
  });
}
function showPasswordError(form, message, fieldName) {
  clearPasswordError(form);
  const error = form.querySelector(".password-error");
  const field = form.elements.namedItem(fieldName);
  if (error) error.textContent = message;
  if (field) {
    field.setAttribute("aria-invalid", "true");
    field.focus();
  }
}
function passwordValues(form, withConfirmation = false) {
  const values = Object.fromEntries(new FormData(form));
  if (!values.current) {
    showPasswordError(form, "Введите текущий пароль", "current");
    return null;
  }
  if (!values.password) {
    showPasswordError(form, "Введите новый пароль", "password");
    return null;
  }
  if ([...values.password].length < PASSWORD_MIN_LENGTH) {
    showPasswordError(
      form,
      `Пароль должен содержать не менее ${PASSWORD_MIN_LENGTH} символов`,
      "password",
    );
    return null;
  }
  if (withConfirmation && !values.confirmation) {
    showPasswordError(form, "Повторите новый пароль", "confirmation");
    return null;
  }
  if (withConfirmation && values.password !== values.confirmation) {
    showPasswordError(form, "Новые пароли не совпадают", "confirmation");
    return null;
  }
  clearPasswordError(form);
  return values;
}
function bindPasswordErrorReset(form) {
  form.addEventListener("input", (event) => {
    if (event.target.matches("input")) clearPasswordError(form);
  });
}
function time(t) {
  return t
    ? new Date(t * 1000).toLocaleString("ru", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "ещё не импортировались";
}
function age(t) {
  let m = Math.max(0, Math.floor((Date.now() / 1000 - t) / 60));
  return m < 1
    ? "только что"
    : m < 60
      ? m + " мин назад"
      : Math.floor(m / 60) + " ч назад";
}
function fileSize(bytes) {
  if (bytes < 1024) return bytes + " Б";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(bytes < 10240 ? 1 : 0) + " КБ";
  return (bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0) + " МБ";
}
let containerCountdown = null;
let containerPoll = null;
function clearContainerTimers() {
  clearInterval(containerCountdown);
  clearTimeout(containerPoll);
  containerCountdown = null;
  containerPoll = null;
}
function remainingContainerTime(expiresAt) {
  if (!expiresAt) return "Время завершения уточняется";
  const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  if (!seconds) return "Время контейнера истекло";
  if (seconds < 60) return `Истекает через ${seconds} сек.`;
  return `Истекает через ${Math.ceil(seconds / 60)} мин.`;
}
function containerConnections(entrypoints) {
  if (!entrypoints?.length) return '<p class="small muted">Точки подключения ещё не готовы.</p>';
  return `<div class="container-endpoints">${entrypoints.map((entrypoint) => {
    const links = (entrypoint.urls || []).map((url) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>`);
    const ports = Object.entries(entrypoint.ports || {}).map(([spec, external]) => {
      const protocol = spec.includes("/") ? spec.split("/")[1] : "tcp";
      const host = entrypoint.host || "";
      if (!host) return "";
      if (entrypoint.connection_type === "ssh") return `<code>ssh -p ${external} user@${esc(host)}</code>`;
      if (entrypoint.connection_type === "http_port" || entrypoint.connection_type === "https_port") {
        const url = `${entrypoint.connection_type === "https_port" ? "https" : "http"}://${host}:${external}`;
        return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>`;
      }
      return `<code>${protocol === "udp" ? "nc -u" : "nc"} ${esc(host)} ${external}</code>`;
    }).filter(Boolean);
    if (!ports.length && entrypoint.host && entrypoint.port) ports.push(`<code>${esc(entrypoint.host)}:${entrypoint.port}</code>`);
    const rows = [...links, ...ports];
    return `<div class="container-endpoint">${entrypoint.slug ? `<span class="small muted">${esc(entrypoint.slug)}</span>` : ""}${rows.join("")}${entrypoint.info ? `<small>${esc(entrypoint.info)}</small>` : ""}</div>`;
  }).join("")}</div>`;
}
function renderContainerState(taskId, mine, state) {
  const section = $("#task-container");
  if (!section || Number(section.dataset.taskId) !== Number(taskId)) return;
  clearInterval(containerCountdown);
  clearTimeout(containerPoll);
  containerCountdown = null;
  containerPoll = null;
  section.setAttribute("aria-busy", "false");
  const status = state.status;
  if (status === "not_found") {
    section.innerHTML = `<div class="container-head"><div><h3>Контейнер</h3><p class="small muted">Не запущен</p></div><span class="container-state idle">Остановлен</span></div><p class="container-copy">Запустите изолированное окружение задачи. Оно будет общим для команды.</p>${mine ? `<button class="primary" data-container-action="start" data-id="${taskId}">Запустить контейнер</button>` : '<p class="small muted">Присоединитесь к задаче, чтобы запустить контейнер.</p>'}<p class="error" id="container-error" role="alert"></p>`;
    return;
  }
  const provisioning = status === "provisioning" || (status === "running" && !state.entrypoints?.length);
  section.innerHTML = `<div class="container-head"><div><h3>Контейнер</h3><p class="small muted" id="container-expiry">${esc(remainingContainerTime(state.expires_at))}</p></div><span class="container-state running"><i></i>${provisioning ? "Запускается" : "Работает"}</span></div>${containerConnections(state.entrypoints)}${mine ? `<div class="container-actions"><button data-container-action="renew" data-id="${taskId}">Продлить на 30 минут</button><button class="quiet-danger" data-container-action="stop" data-id="${taskId}">Завершить контейнер</button></div>` : '<p class="small muted">Управление доступно участникам этой задачи.</p>'}<p class="error" id="container-error" role="alert"></p>`;
  containerCountdown = setInterval(() => {
    const expiry = $("#container-expiry");
    if (expiry) expiry.textContent = remainingContainerTime(state.expires_at);
  }, 1000);
  if (provisioning) containerPoll = setTimeout(() => loadContainer(taskId, mine), 3000);
}
async function loadContainer(taskId, mine) {
  const section = $("#task-container");
  if (!section || Number(section.dataset.taskId) !== Number(taskId)) return;
  section.setAttribute("aria-busy", "true");
  try {
    renderContainerState(taskId, mine, await api(`/tasks/${taskId}/container`));
  } catch (error) {
    section.setAttribute("aria-busy", "false");
    section.innerHTML = `<div class="container-head"><h3>Контейнер</h3><span class="container-state error">Недоступен</span></div><p class="error">${esc(error.message)}</p><button data-container-retry="${taskId}">Повторить</button>`;
  }
}
const standardCategories = ["Web", "Crypto", "Pwn", "Reverse", "Forensics", "Misc"];
const taskCategories = () => [...new Set([...standardCategories, ...(data?.tasks || []).map(t => t.category)])];
const categoryClass = value => standardCategories.includes(value) ? value.toLowerCase() : "misc";
function avatar(m) {
  return `<span class="avatar" title="${esc(m.name)}">${esc(m.name.slice(0, 2).toUpperCase())}</span>`;
}
function avatarStack(people, label, className, stackLimit = 10) {
  const names = people.map((member) => member.name);
  const hiddenAvatars = Math.max(0, people.length - stackLimit);
  return `<div class="${className}" aria-label="${label}: ${esc(names.join(", "))}">${people.slice(0, stackLimit).map(avatar).join("")}${hiddenAvatars ? `<span class="task-team-more" title="Ещё ${hiddenAvatars}" aria-label="Ещё ${hiddenAvatars}">+${hiddenAvatars}</span>` : ""}</div>`;
}
function modal(html) {
  clearContainerTimers();
  clearTaskChatTimer();
  $("#modal").innerHTML = html;
  if (!$("#modal").open) $("#modal").showModal();
}
function close() {
  clearContainerTimers();
  clearTaskChatTimer();
  $("#modal").close();
}
function clearTaskChatTimer() {
  if (taskChatTimer) clearInterval(taskChatTimer);
  taskChatTimer = null;
}
const closeButton =
  '<button type="button" data-action="close" aria-label="Закрыть">×</button>';
async function boot() {
  try {
    try {
      user = await api("/me");
    } catch {
      return authScreen();
    }
    if (user.must_change) return passwordScreen();
    comps = await api("/competitions");
    if (!comps.some((c) => c.id === cid)) cid = comps[0].id;
    await refresh();
    shell();
  } catch (e) {
    $("#app").innerHTML =
      `<div class="empty">${esc(e.message)}<br><button onclick="location.reload()">Повторить</button></div>`;
  }
}
function authScreen() {
  $("#app").innerHTML =
    `<main class="auth"><form class="auth-card" id="auth-form"><div class="brand"><span class="brand-mark">⚑</span> workflow<span class="muted small"> / CTF</span></div><h1>С возвращением</h1><p class="muted">Войдите, чтобы продолжить работу над задачами.</p><label>Логин<input name="login" required autocomplete="username" maxlength="100"></label><label>Пароль<input name="password" type="password" required autocomplete="current-password"></label><p class="error" id="auth-error"></p><button class="primary">Войти в штаб →</button></form></main>`;
  $("#auth-form").onsubmit = async (e) => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target));
    try {
      await api("/login", d);
      await boot();
    } catch (e) {
      $("#auth-error").textContent = e.message;
    }
  };
}
function passwordScreen() {
  $("#app").innerHTML =
    `<main class="auth"><form id="password-form" class="auth-card" novalidate><h1>Новый пароль</h1><p class="muted">Замените временный пароль перед входом.</p><label>Временный пароль<input type="password" name="current" required autocomplete="current-password"></label><label>Новый пароль<input type="password" name="password" minlength="8" required autocomplete="new-password"><span class="field-hint">Не менее 8 символов</span></label><p id="auth-error" class="error password-error" role="alert" aria-live="polite"></p><button class="primary">Сохранить и войти</button></form></main>`;
  const form = $("#password-form");
  bindPasswordErrorReset(form);
  $("#password-form").onsubmit = async (e) => {
    e.preventDefault();
    const values = passwordValues(e.currentTarget);
    if (!values) return;
    try {
      await api("/password", values);
      await boot();
    } catch (e) {
      showPasswordError(form, e.message, e.message.includes("Текущий") ? "current" : "password");
    }
  };
}
async function refresh() {
  data = await api("/board/" + cid);
}
function shell() {
  if (
    !["board", "rating", "captain", "admin"].includes(page) ||
    (["admin", "captain"].includes(page) && !isAdmin())
  )
    page = "board";
  const nav = [
    ["board", "▦", "Доска задач"],
    ["rating", "⌁", "Рейтинг"],
    ...(isAdmin() ? [["captain", "◉", "Обзор капитана"]] : []),
    ...(user.role === "admin" ? [["admin", "⚙", "Администрирование"]] : []),
  ];
  $("#app").innerHTML =
    `<div class="shell"><aside class="sidebar"><div class="brand"><span class="brand-mark">⚑</span> workflow</div><div class="eyebrow">Рабочее пространство</div><nav class="nav">${nav.map(([id, icon, title]) => `<button data-page="${id}" class="${page === id ? "active" : ""}"><span class="nav-icon">${icon}</span>${title}</button>`).join("")}</nav><div class="sidebar-bottom"><div class="connection"><span class="dot"></span>Обновление каждые 5 сек.</div><div class="profile">${avatar(user)}<div class="profile-copy"><strong>${esc(user.name)}</strong><div class="small muted">${roles[user.role]}</div></div><div class="profile-actions"><button class="profile-action" data-action="password" title="Сменить пароль" aria-label="Сменить пароль">Aa</button><button class="profile-action" data-action="logout" title="Выйти" aria-label="Выйти">↗</button></div></div></div></aside><main class="main"><header class="topbar"><div class="topbar-right"><span class="creator-credit">Flagroom</span><button class="mobile-account-action" data-action="password" aria-label="Сменить пароль">Aa</button><button class="mobile-logout" data-action="logout" aria-label="Выйти">↗</button></div></header><div class="content page-enter" id="content"></div></main></div>`;
  renderPage();
  requestAnimationFrame(() => $("#content")?.classList.remove("page-enter"));
}
function heading(title, desc, action = "") {
  return `<div class="heading"><div><h1>${title}</h1><p class="muted">${desc}</p></div>${action}</div>`;
}
function renderPage() {
  if (page === "board") renderBoard();
  if (page === "rating") renderRating();
  if (page === "captain") renderCaptain();
  if (page === "admin") renderAdmin();
}
function renderBoard() {
  let t = data.tasks,
    solved = t.filter((t) => t.status === "solved"),
    active = t.filter((t) => ["working", "stuck", "flag"].includes(t.status));
  $("#content").innerHTML =
    heading(
      "Доска задач",
      "Каждая задача на виду. Вся команда в контексте.",
      isAdmin()
        ? '<button class="primary" data-action="new-task">＋ Добавить задачу</button>'
        : "",
    ) +
    `<div class="metrics"><div class="metric"><span class="muted">Решено задач</span><span class="mini">✓</span><div class="value">${solved.length} <span>/ ${t.length}</span></div></div><div class="metric"><span class="muted">В работе</span><span class="mini">◷</span><div class="value">${active.length} <span>задач</span></div></div><div class="metric"><span class="muted">Нужна помощь</span><span class="mini">⚐</span><div class="value">${t.filter((t) => t.status === "stuck").length} <span>задач</span></div></div></div>` +
    `<div class="toolbar"><div class="tabs">${["Все", ...taskCategories()].map((c) => `<button data-category="${esc(c)}" class="${category === c ? "active" : ""}">${esc(c)}</button>`).join("")}</div></div><div id="board" class="board"></div>`;
  renderColumns();
}
function renderRating() {
  const rating = data.rating || [];
  const enterClass = ratingEntered ? "" : " rating-enter";
  $("#content").innerHTML =
    heading(
      "Рейтинг",
      "Места определяются количеством подтверждённых решений.",
    ) +
    `<section class="leaderboard" aria-label="Рейтинг участников"><div class="leaderboard-head"><span>№ п/п</span><span>Фамилия</span><span>Решено</span></div><ol class="leaderboard-list">${rating.map((member, index) => {
      const place = index + 1;
      const tier = place <= 5 ? ` rank-${place}` : "";
      return `<li class="leaderboard-row${tier}${enterClass}" style="--row-index:${Math.min(index, 12)}"><span class="rank-place">${place}</span><span class="rank-person">${avatar(member)}<strong>${esc(member.name)}</strong></span><span class="rank-score"><strong>${member.solved}</strong><small>задач</small></span></li>`;
    }).join("")}</ol></section>`;
  ratingEntered = true;
}
function renderColumns() {
  const tasks = data.tasks.filter(
    (t) => category === "Все" || t.category === category,
  );
  $("#board").innerHTML = ["free", "working", "stuck", "solved"]
    .map((s) => {
      let ts = tasks.filter(
        (t) => t.status === s,
      );
      return `<section class="status-column" data-status="${s}" aria-label="${statuses[s]}"><div class="column-head ${s}"><span class="line"></span>${statuses[s]} <span class="count">${ts.length}</span></div><div class="task-list">${ts.map(card).join("")}</div></section>`;
    })
    .join("");
}
function card(t) {
  const mine = t.members.some((m) => m.id === user.id);
  const people = t.status === "solved" ? (t.authors || []) : t.members;
  const peopleLabel = t.status === "solved" ? "Флаг сдал" : "Работают над задачей";
  const actions = t.status === "solved"
    ? '<span class="small task-accepted">✓ Решено</span>'
    : mine
      ? `<div class="task-card-actions"><button data-task-action="${t.status === "stuck" ? "work" : "help"}" data-id="${t.id}">${t.status === "stuck" ? "В работу" : "Нужна помощь"}</button><button class="quiet-danger" data-task-action="leave" data-id="${t.id}">Отказаться</button></div>`
      : `<button class="primary" data-join="${t.id}" ${t.external_available === 0 ? "disabled" : ""}>Присоединиться</button>`;
  return `<article class="task${mine && t.status === "working" ? " task-mine" : ""}" data-task="${t.id}" tabindex="0" role="button" aria-label="Открыть ${esc(t.title)}${mine ? ", вы участвуете" : ""}"><div class="task-top"><span class="tag ${categoryClass(t.category)}">${esc(t.category)}</span></div><h3>${esc(t.title)}</h3><p class="task-difficulty">Сложность: <span>${esc(t.difficulty || "Не указана")}</span></p><p class="task-desc">${esc(t.description || "Описание пока не добавлено.")}</p>${t.external_available === 0 ? '<div class="small muted">Недоступна в источнике</div>' : ""}<div class="task-meta"><span>${age(t.updated_at)}</span></div>${people.length ? avatarStack(people, peopleLabel, "task-card-team", 9) : ""}<div class="task-bottom">${actions}</div></article>`;
}
function taskChatMessage(message) {
  const own = message.author_id === user.id ? " own" : "";
  const author = message.author || "Перенесённая заметка";
  return `<article class="task-chat-message${own}">${avatar({name: author})}<div class="task-chat-bubble"><div class="task-chat-meta"><strong>${esc(author)}</strong><time datetime="${new Date(message.created_at * 1000).toISOString()}">${time(message.created_at)}</time></div><p>${esc(message.body)}</p></div></article>`;
}
async function loadTaskChat(id, keepPosition = false) {
  const list = $("#task-chat-messages");
  if (!list) return;
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 48;
  const messages = await api(`/tasks/${id}/chat`);
  if (!$("#task-chat-messages")) return;
  list.innerHTML = messages.length
    ? messages.map(taskChatMessage).join("")
    : '<p class="task-chat-empty muted">Сообщений пока нет. Начните обсуждение задачи.</p>';
  if (!keepPosition || nearBottom) list.scrollTop = list.scrollHeight;
}
async function openTaskChat(id) {
  const panel = $("#task-chat-panel");
  const button = $(`[data-open-task-chat="${id}"]`);
  if (!panel || !button) return;
  const opening = panel.hidden;
  panel.hidden = !opening;
  button.setAttribute("aria-expanded", String(opening));
  button.textContent = opening ? "Закрыть чат" : "Открыть чат";
  clearTaskChatTimer();
  if (!opening) return;
  await loadTaskChat(id);
  const form = $("#task-chat-form");
  form.onsubmit = async (event) => {
    event.preventDefault();
    const input = form.elements.message;
    const submit = form.querySelector("button");
    const message = input.value.trim();
    if (!message) return input.focus();
    submit.disabled = true;
    try {
      await api(`/tasks/${id}/chat`, { message });
      input.value = "";
      await loadTaskChat(id);
      input.focus();
    } catch (error) {
      $("#task-chat-error").textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  };
  taskChatTimer = setInterval(() => loadTaskChat(id, true).catch(() => {}), 4000);
}
async function openTask(id) {
  await refresh();
  const t = data.tasks.find((t) => t.id === Number(id));
  if (!t) return toast("Задача не найдена");
  const mine = t.members.some((m) => m.id === user.id);
  const people = t.status === "solved" ? (t.authors || []) : t.members;
  const taskActions = t.status === "solved"
    ? '<span class="task-accepted">✓ Решено</span>'
    : mine
      ? `<div class="task-work-actions"><button data-task-action="${t.status === "stuck" ? "work" : "help"}" data-id="${t.id}">${t.status === "stuck" ? "Вернуться в работу" : "Нужна помощь"}</button><button class="quiet-danger" data-task-action="leave" data-id="${t.id}">Отказаться</button></div>`
      : `<button class="primary" data-task-action="join" data-id="${t.id}">Присоединиться</button>`;
  const participantSection = mine
    ? `<hr class="divider"><section class="task-participant-tools">${t.status !== "solved" ? `<section class="flag-submit"><label for="task-flag">Флаг</label><div class="flag-submit-row"><input id="task-flag" name="flag" maxlength="4096" autocomplete="off" spellcheck="false" placeholder="flag{…}"><button type="button" class="primary" data-submit-flag="${t.id}">Сдать флаг</button></div><p class="error" id="flag-error" role="alert"></p></section>` : ""}<button type="button" class="task-chat-toggle" data-open-task-chat="${t.id}" aria-expanded="false" aria-controls="task-chat-panel">Открыть чат</button><section class="task-chat-panel" id="task-chat-panel" hidden><div class="task-chat-head"><div><h3>Чат задачи</h3><p class="small muted">Обсуждение видят участники этой задачи</p></div></div><div class="task-chat-messages" id="task-chat-messages" aria-live="polite"></div><form class="task-chat-form" id="task-chat-form"><textarea name="message" maxlength="4000" required placeholder="Напишите сообщение…" aria-label="Сообщение в чат"></textarea><button class="primary">Отправить</button></form><p class="error" id="task-chat-error" role="alert"></p></section></section>`
    : "";
  const files = t.files?.length
    ? `<section class="task-files"><h3>Файлы задания</h3><div class="task-file-list">${t.files.map((file) => `<a class="task-file" href="/api/task-files/${file.id}" download><span>${esc(file.filename)}</span><small>${fileSize(file.size)}</small></a>`).join("")}</div></section>`
    : "";
  const container = t.container_enabled
    ? `<section class="task-container" id="task-container" data-task-id="${t.id}" aria-live="polite" aria-busy="true"><div class="container-loading"><i></i><span>Получаем состояние контейнера…</span></div></section>`
    : "";
  modal(
    `<div class="dialog-head"><div><span class="tag ${categoryClass(t.category)}">${esc(t.category)}</span><h2>${esc(t.title)}</h2><span class="muted">Сложность: ${esc(t.difficulty || "Не указана")} · ${statuses[t.status]}</span></div>${closeButton}</div><p class="detail-desc" style="margin-top:20px">${esc(t.description || "Описание пока не добавлено.")}</p>${files}${container}${t.source_evidence?.[0] ? `<details class="source-evidence"><summary>Фрагмент страницы, использованный ИИ-парсером</summary><p class="small muted">${esc(t.source_evidence[0].evidence)}</p></details>` : ""}<div class="task-workbar">${people.length ? avatarStack(people, t.status === "solved" ? "Флаг сдал" : "Работают над задачей", "task-team-icons") : `<p class="task-team-empty">${t.status === "solved" ? "Решивший участник не указан" : "Пока никто не работает"}</p>`}${taskActions}</div>${participantSection}`,
  );
  if (t.container_enabled) loadContainer(t.id, mine);
  const flagInput = $("#task-flag");
  if (flagInput) flagInput.onkeydown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      flagInput.closest(".flag-submit").querySelector("button").click();
    }
  };
}
async function renderCaptain() {
  if (!isAdmin()) return;
  const target = cid;
  const title = heading("Обзор капитана", "Занятость и решения участников.");
  if (!$("#captain-stats")) $("#content").innerHTML = title + '<p class="muted">Загрузка…</p>';
  try {
    const stats = await api("/admin/stats/" + target);
    if (page !== "captain" || cid !== target || !isAdmin()) return;
    $("#content").innerHTML = title + `<div class="panel" id="captain-stats"><h2>Статистика участников <span class="muted">${stats.length}</span></h2><div class="table-wrap"><table class="captain-table"><thead><tr><th scope="col">Участник</th><th scope="col">Занятость</th><th scope="col">В работе</th><th scope="col">Нужна помощь</th><th scope="col">Решено</th><th scope="col">Очки</th><th scope="col">Текущие задачи</th></tr></thead><tbody>${stats.map(s => `<tr class="${s.needs_help ? "member-help" : s.occupied ? "" : "member-idle"}" data-member="${s.id}"><td><span class="row">${avatar(s)}<strong>${esc(s.name)}</strong></span>${s.active ? "" : '<span class="small muted">Доступ отключён</span>'}</td><td><span class="member-status">${s.needs_help ? "Нужна помощь" : s.occupied ? "В работе" : "Сидит без дела"}</span></td><td>${s.working}</td><td>${s.needs_help}</td><td>${s.solved}</td><td>${s.points}</td><td>${s.tasks.map(t => `<a href="#task-${t.id}">${esc(t.title)}</a>`).join(", ") || "—"}</td></tr>`).join("")}</tbody></table></div></div>`;
  } catch (e) {
    if (page === "captain") toast(e.message);
  }
}
async function renderAdmin() {
  if (!isAdmin()) return;
  const target = cid;
  $("#content").innerHTML = heading("Администрирование", "Участники и подключение площадки.") + '<p class="muted">Загрузка…</p>';
  try {
    const [users, source] = await Promise.all([
      api("/admin/users"),
      api("/admin/source/" + target),
    ]);
    if (page !== "admin" || cid !== target || !isAdmin()) return;
    $("#content").innerHTML = heading(
      "Администрирование",
      "Участники и подключение площадки.",
      '<button class="primary" data-action="new-users">＋ Создать участников</button>',
    ) + `<div class="panel"><h2>Парсер площадки</h2><div id="source-status">${sourceStatus(source)}</div><div class="row" style="flex-wrap:wrap"><button class="primary" data-action="source">Настроить источник</button><button data-action="sync-source" ${source.enabled ? "" : "disabled"}>Обновить сейчас</button><button data-action="import">Импорт JSON</button></div></div><div class="panel"><h2>Участники <span class="muted">${users.length}</span></h2><div class="table-wrap"><table class="users-table"><thead><tr><th scope="col">Участник — фамилия</th><th scope="col">Логин</th><th scope="col">Пароль</th><th scope="col">Роль</th><th scope="col" aria-label="Управление"></th></tr></thead><tbody>${users.map(u => `<tr data-member="${u.id}"><td>${esc(u.name)}${u.active ? "" : '<div class="small muted">Доступ отключён</div>'}</td><td>${esc(u.login)}</td><td class="user-password">${u.password ? `<code>${esc(u.password)}</code>` : '<span class="small muted">Появится после входа или сброса</span>'}</td><td>${roles[u.role]}</td><td>${u.id !== user.id ? `<button data-user="${u.id}">Управление</button>` : "Вы"}</td></tr>`).join("")}</tbody></table></div></div>`;
    window.adminUsers = users;
  } catch (e) {
    if (page === "admin") toast(e.message);
  }
}
const sourceStates = {
  idle: "Обновление выключено", queued: "Ожидаем обработчик", running: "Подключаемся",
  ready: "Подключено", needs_action: "Требуется действие", incomplete: "Неполная выгрузка", error: "Ошибка обновления",
};
function sourceStatus(source) {
  if (!source.url) return '<p class="muted">Подключите площадку — задачи появятся на доске автоматически.</p>';
  const state = source.enabled ? (source.status || "queued") : "idle";
  return `<div class="source-state" role="status"><span class="source-indicator ${["ready", "running", "queued"].includes(state) ? state : ""}"></span><strong>${esc(sourceStates[state] || state)}</strong></div>
    <p class="small muted source-url">${esc(source.url)}</p>
    ${source.stage && source.enabled ? `<p class="small">${esc(source.stage)}</p>` : ""}
    <p class="small muted">${source.enabled ? "Обновление каждые " + source.interval_seconds + " сек." : "Автообновление выключено"} · ${esc(source.parser || source.mode).toUpperCase()}<br>
    Успешное обновление: ${time(source.last_success)}${source.task_count !== undefined ? " · " + source.task_count + " задач" : ""}</p>
    ${source.error ? `<p class="error">${esc(source.error)}${state !== "needs_action" ? `<br>Следующая попытка: ${time(source.next_run)}` : "<br>Обновите доступ в настройках источника."}</p>` : ""}`;
}
async function sourceDialog() {
  const source = await api("/admin/source/" + cid);
  modal(`<div class="dialog-head"><div><h2>Подключить площадку</h2><p class="muted">Сервер войдёт в аккаунт и перенесёт задачи на доску.</p></div>${closeButton}</div>
    <form id="source-form" autocomplete="off">
      <label>Ссылка на площадку<input name="url" type="url" required value="${esc(source.url)}" placeholder="https://ctf.example"></label>
      <label>Способ входа<select name="auth_method"><option value="password">Логин и пароль</option><option value="cookie">Cookies</option><option value="token">API-токен CTFd</option><option value="none">Без авторизации</option><option value="server">Доступ из настроек сервера</option></select></label>
      <div data-auth-fields="password" class="grid-two source-auth-fields">
        <label>Логин или email<input name="source_username" autocomplete="off" maxlength="4096" placeholder="Логин на CTF-площадке"></label>
        <label>Пароль<input name="source_password" type="password" autocomplete="new-password" maxlength="4096" placeholder="Пароль на CTF-площадке"></label>
      </div>
      <div data-auth-fields="cookie" class="source-auth-fields hidden"><label>Значение заголовка Cookie<textarea name="source_cookie" spellcheck="false" maxlength="16384" placeholder="session=…; other_cookie=…"></textarea></label></div>
      <div data-auth-fields="token" class="source-auth-fields hidden"><label>API-токен<input name="source_token" type="password" autocomplete="new-password" maxlength="4096"></label></div>
      <p class="small muted" id="source-auth-help"></p>
      <details class="source-advanced"><summary>Параметры сбора</summary>
        <div class="grid-two"><label>Способ разбора<select name="mode"><option value="auto">Автоматически</option><option value="ctfd">Только CTFd API</option><option value="ai">ИИ: страница или JSON</option></select></label>
        <label>Интервал, секунды<input name="interval_seconds" type="number" min="60" max="3600" value="${source.interval_seconds}" required></label></div>
      </details>
      <div class="checks"><label><input type="checkbox" name="enabled" ${!source.url || source.enabled ? "checked" : ""}>Автоматически обновлять задачи</label></div>
      <p class="small muted">Для неизвестной площадки используется ИИ-разбор содержимого задач. Данные входа модели не передаются. CAPTCHA и двухфакторный вход могут потребовать cookies после ручного входа.</p>
      <p class="error" id="source-error" role="alert"></p>
      <div class="source-actions"><button class="primary" type="submit">Проверить и подключить</button>${source.has_credentials ? '<button type="button" id="clear-source-auth">Удалить доступ</button>' : ""}</div>
    </form>`);
  const form = $("#source-form");
  form.elements.mode.value = source.mode;
  form.elements.auth_method.value = source.auth_method;
  const updateFields = () => {
    const method = form.elements.auth_method.value;
    const saved = source.has_credentials && method === source.auth_method;
    form.querySelectorAll("[data-auth-fields]").forEach(element => {
      const visible = element.dataset.authFields === method;
      element.classList.toggle("hidden", !visible);
      element.querySelectorAll("input,textarea").forEach(input => { input.disabled = !visible; input.required = visible && !saved; });
    });
    $("#source-auth-help").textContent = saved ? "Доступ сохранён. Оставьте поля пустыми, чтобы его сохранить, или введите новые данные." : method === "none" ? "Подходит для открытого списка задач." : method === "server" ? "Используется доступ, заданный в .env для этого адреса." : "Доступ хранится в зашифрованном виде и используется только для этой площадки.";
  };
  form.elements.auth_method.onchange = updateFields;
  updateFields();
  form.onsubmit = async (event) => {
    event.preventDefault();
    const button = form.querySelector('[type="submit"]');
    const f = new FormData(form);
    const auth = {method: f.get("auth_method")};
    for (const key of ["username", "password", "cookie", "token"]) if (f.get("source_" + key)) auth[key] = f.get("source_" + key);
    button.disabled = true;
    $("#source-error").textContent = "";
    try {
      await api("/admin/source/" + cid, {url: f.get("url"), mode: f.get("mode"), interval_seconds: Number(f.get("interval_seconds")), enabled: f.has("enabled"), auth});
      form.reset();
      close();
      await renderAdmin();
      toast("Подключение поставлено в очередь");
    } catch (error) {
      $("#source-error").textContent = error.message;
    } finally { button.disabled = false; }
  };
  if ($("#clear-source-auth")) $("#clear-source-auth").onclick = () => run(async () => {
    await api("/admin/source/" + cid, {action: "clear_auth"});
    form.reset(); close(); await renderAdmin(); toast("Доступ удалён, обновление выключено");
  });
}
function newTask() {
  if (!isAdmin()) return;
  modal(
    `<div class="dialog-head"><h2>Новая задача</h2>${closeButton}</div><form id="new-task-form"><label>Название<input name="title" required maxlength="150"></label><div class="grid-two"><label>Категория<select name="category">${taskCategories().map((c) => `<option>${esc(c)}</option>`).join("")}</select></label><label>Очки<input type="number" name="points" min="0" value="100" required></label></div><label>Описание и ссылки<textarea name="description"></textarea></label><button class="primary">Создать задачу</button></form>`,
  );
  $("#new-task-form").onsubmit = (e) => {
    e.preventDefault();
    run(async () => {
      await api("/tasks", {
        ...Object.fromEntries(new FormData(e.target)),
        competition_id: cid,
      });
      close();
      await updateBackground();
    });
  };
}
function newUsers() {
  modal(
    `<div class="dialog-head"><h2>Создать участников</h2>${closeButton}</div><form id="users-form"><label>Фамилии — по одной на строку<textarea name="names" placeholder="Иванов\nПетров\nСидоров"></textarea></label><label>Или количество автоматических профилей<input name="count" type="number" value="25" min="1" max="100"></label><label>Роль<select name="role"><option value="member">Участник</option><option value="captain">Капитан</option></select></label><p class="small muted">Пароли доступны в таблице участников. Передайте каждому участнику его доступы.</p><button class="primary">Сгенерировать аккаунты</button></form>`,
  );
  $("#users-form").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    run(async () => {
      const creds = await api("/admin/users", {
        names: f
          .get("names")
          .split("\n")
          .filter((n) => n.trim()),
        count: Number(f.get("count")),
        role: f.get("role"),
      });
      const text = creds
        .map((c) => `${c.name}\t${c.login}\t${c.password}`)
        .join("\n");
      modal(
        `<div class="dialog-head"><h2>Доступы созданы</h2>${closeButton}</div><p class="muted">Доступы также сохранены в таблице участников.</p><pre class="credentials">${esc(text)}</pre><button id="download" class="primary">Скачать TSV</button>`,
      );
      $("#download").onclick = () => {
        const url = URL.createObjectURL(
          new Blob(["Фамилия\tЛогин\tПароль\n" + text], {
            type: "text/tab-separated-values;charset=utf-8",
          }),
        );
        const a = document.createElement("a");
        a.href = url;
        a.download = "ctf-accounts.tsv";
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      };
      await updateBackground();
    });
  };
}
function importDialog() {
  modal(
    `<div class="dialog-head"><h2>Импорт таблицы соревнования</h2>${closeButton}</div><p class="muted">Загрузите JSON-массив задач. Совпадение по точному названию обновляет очки и число решений; прогресс и участники сохраняются.</p><pre class="credentials">[{"title":"Cookie Monster","category":"Web",\n  "points":250,"solves":42}]</pre><form id="import-form"><label>JSON-файл<input id="import-file" type="file" accept=".json,application/json"></label><label>Или вставьте JSON<textarea id="import-json" placeholder='[{"title":"...","category":"Web","points":100,"solves":20}]'></textarea></label><button class="primary">Импортировать</button></form>`,
  );
  $("#import-form").onsubmit = (e) => {
    e.preventDefault();
    run(async () => {
      let file = $("#import-file").files[0];
      let text = file ? await file.text() : $("#import-json").value;
      let tasks;
      try {
        tasks = JSON.parse(text);
      } catch {
        throw Error("Некорректный JSON");
      }
      await api("/import/" + cid, { tasks });
      close();
      await updateBackground();
      toast("Таблица обновлена");
    });
  };
}
function editUser(id) {
  const u = window.adminUsers.find((u) => u.id === id);
  modal(
    `<div class="dialog-head"><h2>${esc(u.name)}</h2>${closeButton}</div><form id="edit-user-form"><label>Фамилия<input name="name" required maxlength="80" value="${esc(u.name)}"></label><label>Роль<select name="role">${Object.entries(
      roles,
    )
      .map(
        ([k, v]) =>
          `<option value="${k}" ${u.role === k ? "selected" : ""}>${v}</option>`,
      )
      .join(
        "",
      )}</select></label><label>Доступ<select name="active"><option value="1" ${u.active ? "selected" : ""}>Активен</option><option value="0" ${!u.active ? "selected" : ""}>Отключён</option></select></label><div class="row" style="margin-top:20px"><button class="primary">Сохранить</button><button type="button" id="reset-password">Сбросить пароль</button></div></form>`,
  );
  $("#edit-user-form").onsubmit = (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target));
    run(async () => {
      await api("/admin/users/" + id, {
        name: f.name,
        role: f.role,
        active: f.active === "1",
      });
      close();
      await renderAdmin();
    });
  };
  $("#reset-password").onclick = () =>
    run(async () => {
      const r = await api("/admin/users/" + id, { action: "reset" });
      modal(
        `<div class="dialog-head"><h2>Новый временный пароль</h2>${closeButton}</div><p>${esc(u.login)}</p><pre class="credentials">${esc(r.password)}</pre>`,
      );
      await renderAdmin();
    });
}
function changePassword() {
  modal(
    `<div class="dialog-head"><div><h2>Сменить пароль</h2><p class="muted">Новый пароль сразу появится в таблице администратора.</p></div>${closeButton}</div><form id="change-password-form" novalidate><label>Текущий пароль<input type="password" name="current" required autocomplete="current-password"></label><label>Новый пароль<input type="password" name="password" minlength="8" required autocomplete="new-password"><span class="field-hint">Не менее 8 символов</span></label><label>Повторите новый пароль<input type="password" name="confirmation" minlength="8" required autocomplete="new-password"></label><p id="password-error" class="error password-error" role="alert" aria-live="polite"></p><button class="primary">Сохранить новый пароль</button></form>`,
  );
  const passwordForm = $("#change-password-form");
  bindPasswordErrorReset(passwordForm);
  passwordForm.onsubmit = async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const values = passwordValues(form, true);
    if (!values) return;
    const button = form.querySelector('button[type="submit"], button:not([type])');
    button.disabled = true;
    try {
      await api("/password", { current: values.current, password: values.password });
      form.reset();
      close();
      if (page === "admin" && isAdmin()) await renderAdmin();
      toast("Пароль изменён");
    } catch (error) {
      showPasswordError(form, error.message, error.message.includes("Текущий") ? "current" : "password");
    } finally {
      button.disabled = false;
    }
  };
}
async function run(fn) {
  try {
    await fn();
  } catch (e) {
    toast(e.message);
  }
}
async function updateBackground() {
  await refresh();
  if (page === "board") renderBoard();
  else if (page === "rating") renderRating();
  else if (page === "captain") renderCaptain();
  else if (page === "admin") await renderAdmin();
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("button,a,[data-task]");
  if (!b) return;
  if (b.tagName === "A" && /^#task-\d+$/.test(b.getAttribute("href") || "")) {
    e.preventDefault();
    return run(() => openTask(Number(b.getAttribute("href").slice(6))));
  }
  if (b.dataset.join) {
    e.stopPropagation();
    return run(async () => {
      await api("/tasks/" + b.dataset.join, { action: "join" });
      await updateBackground();
      toast("Вы присоединились к задаче");
    });
  }
  if (b.dataset.openTaskChat) {
    e.preventDefault();
    return run(() => openTaskChat(Number(b.dataset.openTaskChat)));
  }
  if (b.dataset.submitFlag) {
    e.preventDefault();
    return run(async () => {
      const input = $("#task-flag");
      const error = $("#flag-error");
      const flag = input?.value.trim() || "";
      if (!flag) {
        error.textContent = "Введите флаг";
        input?.focus();
        return;
      }
      error.textContent = "";
      b.disabled = true;
      const label = b.textContent;
      b.textContent = "Проверяем…";
      try {
        const queued = await api("/tasks/" + b.dataset.submitFlag + "/flag", { flag });
        b.textContent = "В очереди…";
        const result = await waitForFlag(queued.job_id);
        if (!["correct", "partial"].includes(result.status))
          throw Error(result.message || "CTFd не подтвердила флаг");
        input.value = "";
        toast(result.message || "Флаг проверен");
        await openTask(b.dataset.submitFlag);
        await updateBackground();
      } catch (problem) {
        error.textContent = problem.message;
        input.focus();
        input.select();
      } finally {
        b.disabled = false;
        b.textContent = label;
      }
    });
  }
  if (b.dataset.containerRetry) {
    const task = data.tasks.find((item) => item.id === Number(b.dataset.containerRetry));
    return loadContainer(Number(b.dataset.containerRetry), Boolean(task?.members.some((member) => member.id === user.id)));
  }
  if (b.dataset.containerAction) {
    const taskId = Number(b.dataset.id);
    const task = data.tasks.find((item) => item.id === taskId);
    const mine = Boolean(task?.members.some((member) => member.id === user.id));
    const action = b.dataset.containerAction;
    return (async () => {
      const section = $("#task-container");
      const buttons = section ? [...section.querySelectorAll("button")] : [];
      buttons.forEach((button) => { button.disabled = true; });
      section?.setAttribute("aria-busy", "true");
      if (action === "start") {
        renderContainerState(taskId, mine, {status: "provisioning", expires_at: null, entrypoints: []});
      }
      try {
        const state = await api(`/tasks/${taskId}/container`, {action});
        renderContainerState(taskId, mine, state);
        toast({start: "Контейнер запускается", renew: "Время контейнера продлено", stop: "Контейнер остановлен"}[action]);
      } catch (error) {
        if (action === "start") {
          renderContainerState(taskId, mine, {status: "not_found", expires_at: null, entrypoints: []});
        }
        const target = $("#container-error");
        if (target) target.textContent = error.message;
        else toast(error.message);
        section?.setAttribute("aria-busy", "false");
        buttons.forEach((button) => { button.disabled = false; });
      }
    })();
  }
  if (b.dataset.task) return run(() => openTask(b.dataset.task));
  if (b.dataset.page) {
    page = b.dataset.page;
    shell();
    return;
  }
  if (b.dataset.category) {
    category = b.dataset.category;
    renderBoard();
    return;
  }
  if (b.dataset.taskAction)
    return run(async () => {
      const task = data.tasks.find((item) => item.id === Number(b.dataset.id));
      const form = $("#task-form");
      const fromCard = Boolean(b.closest("article.task"));
      const body = { action: b.dataset.taskAction };
      if (["help", "work"].includes(body.action) && task) {
        const progress = form ? new FormData(form).get("progress") : task.progress;
        if (form && progress !== task.progress) {
          body.progress_revision = task.progress_revision;
          body.progress = progress;
        }
      }
      await api("/tasks/" + b.dataset.id, body);
      if (fromCard) {
        await updateBackground();
      } else {
        await openTask(b.dataset.id);
        await updateBackground();
      }
    });
  if (b.dataset.user) return editUser(Number(b.dataset.user));
  const actions = {
    source: () => run(sourceDialog),
    "sync-source": () =>
      run(async () => {
        await api("/admin/source/" + cid, { action: "sync" });
        toast("Синхронизация запланирована");
        await renderAdmin();
      }),
    close: close,
    logout: () =>
      run(async () => {
        await api("/logout", {});
        window.adminUsers = null;
        user = null;
        data = null;
        page = "board";
        ratingEntered = false;
        close();
        $("#modal").replaceChildren();
        authScreen();
      }),
    "new-task": newTask,
    "new-users": newUsers,
    password: changePassword,
    import: importDialog,
  };
  if (actions[b.dataset.action]) actions[b.dataset.action]();
});
document.addEventListener("keydown", (e) => {
  if (
    (e.key === "Enter" || e.key === " ") &&
    e.target.matches("article[data-task]")
  ) {
    e.preventDefault();
    run(() => openTask(e.target.dataset.task));
  }
});
window.addEventListener("hashchange", () => {
  const m = location.hash.match(/^#task-(\d+)$/);
  if (m && data) run(() => openTask(Number(m[1])));
});
setInterval(async () => {
  if (!user || user.must_change || !data || document.hidden) return;
  try {
    await refresh();
    if (page === "board" && !$("#modal").open)
      renderBoard();
    if (page === "rating" && !$("#modal").open) renderRating();
    if (page === "captain" && !$("#modal").open) renderCaptain();
    if (page === "admin" && !$("#modal").open) {
      const source = await api("/admin/source/" + cid);
      if ($("#source-status"))
        $("#source-status").innerHTML = sourceStatus(source);
    }
  } catch {}
}, 5000);
$("#modal").addEventListener("close", () => {
  clearTaskChatTimer();
  const form = $("#source-form");
  if (form) form.reset();
});
boot();
