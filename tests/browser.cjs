const { chromium } = require("playwright");
const fs = require("node:fs");
const assert = require("node:assert/strict");
(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.CHROMIUM_PATH || undefined,
  });
  const page = await browser.newPage({
    viewport: { width: 1512, height: 982 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(process.env.TEST_URL || "http://127.0.0.1:5001");
  await page.locator("[name=login]").fill("browser-admin");
  await page.locator("[name=password]").fill("browser-test-password");
  await page.getByRole("button", { name: "Войти в штаб" }).click();
  await page
    .getByRole("heading", { name: "Доска задач", exact: true })
    .waitFor();
  await page.waitForFunction(() => getComputedStyle(document.querySelector("#content")).opacity === "1");
  const request = async (path, body) =>
    page.evaluate(
      async ({ path, body }) => {
        const r = await fetch("/api" + path, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "CTFBoard",
          },
          body: JSON.stringify(body),
        });
        if (!r.ok) throw Error(await r.text());
        return r.json();
      },
      { path, body },
    );
  await request("/import/1", {
    tasks: JSON.parse(fs.readFileSync("examples/scoreboard.json", "utf8")).map((task, index) => ({...task, difficulty: index === 0 ? "Easy" : null})),
  });
  const accounts = await request("/admin/users", {
    names: ["alice", "nullbyte", "hex", "morph", "cipher", "r00t"],
  });
  await page.reload();
  await page
    .getByRole("heading", { name: "Cookie Monster", exact: true })
    .waitFor();
  await page.locator('article[data-task="1"] [data-join]').click();
  await page.locator('article[data-task="1"] .task-difficulty').getByText("Easy", {exact:true}).waitFor();
  await page.locator('article[data-task="2"] .task-difficulty').getByText("Не указана", {exact:true}).waitFor();
  await page
    .locator('article[data-task="1"]')
    .getByRole("button", { name: "Нужна помощь" })
    .waitFor();
  await page.locator('article[data-task="1"]').click();
  assert.equal(await page.locator('#task-form, [name="progress"], [name="status"], [name="authors"], #hyp-form').count(), 0);
  await page.locator("#modal").getByRole("button", { name: "Нужна помощь", exact: true }).waitFor();
  await page.locator("#modal").getByRole("button", { name: "Отказаться", exact: true }).waitFor();
  await page.locator("#modal").getByLabel("Флаг", { exact: true }).waitFor();
  await page.locator("#modal").getByRole("button", { name: "Сдать флаг", exact: true }).waitFor();
  await page.locator("#modal").getByRole("button", { name: "Открыть чат", exact: true }).click();
  await page.locator("#task-chat-form").getByLabel("Сообщение в чат").fill("Проверяем подпись cookie. Скрипт: scripts/cookie.py");
  await page.locator("#task-chat-form").getByRole("button", { name: "Отправить" }).click();
  const ownMessage = page.locator(".task-chat-message.own").filter({hasText: "Проверяем подпись cookie"});
  await ownMessage.waitFor();
  assert.equal(await ownMessage.locator(".avatar").count(), 1);
  assert.equal(await ownMessage.locator("strong").innerText(), "captain");
  await page.screenshot({path: "instance/task-chat-desktop.png"});
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({path: "instance/task-chat-mobile.png"});
  await page.setViewportSize({width: 1512, height: 982});
  assert.equal(await page.getByRole("button", { name: "Решено", exact: false }).count(), 0);
  await page.getByRole("button", { name: "Закрыть", exact: true }).click();
  await request("/tasks/2", { action: "join" });
  await request("/tasks/2", {
    action: "help",
    progress: "Решение через общий множитель.",
  });
  await request("/tasks/3", { action: "join" });
  await request("/tasks/3", {
    action: "help",
    progress: "Нашли переполнение, нужна помощь с обходом защиты.",
  });
  await request("/tasks/5", { action: "join" });
  await request("/tasks/5", {
    action: "help",
    progress: "Восстанавливаем таблицу переходов.",
  });
  await request("/tasks/10", { action: "join" });
  await request("/tasks/10", {
    action: "progress",
    progress: "Флаг подготовлен к отправке.",
  });
  await page.reload();
  await page
    .getByRole("heading", { name: "Доска задач", exact: true })
    .waitFor();
  await page.screenshot({ path: "instance/board-desktop.png", fullPage: true });
  assert.equal(await page.locator('[data-page=assistant], .overview, #competition').count(), 0);
  assert.equal(await page.getByText("Командные очки", { exact: true }).count(), 0);
  assert.equal(await page.locator(".creator-credit").innerText(), "Flagroom");
  assert((await page.locator("body").evaluate(element => getComputedStyle(element).fontFamily)).includes("Onest"));
  assert(await page.evaluate(() => document.fonts.check('14px "Onest"')));
  assert.equal(await page.locator("#content.page-enter").count(), 0);
  const lanes = await page.locator(".status-column").evaluateAll(columns => columns.map(column => {
    const r = column.getBoundingClientRect();
    return { x: r.x, y: r.y, width: r.width };
  }));
  assert.equal(lanes.length, 4);
  assert(lanes.every((column, i) => column.y === lanes[0].y && (!i || column.x > lanes[i - 1].x)));
  const separator = await page.locator('.status-column[data-status="working"]').evaluate(element => ({
    style: getComputedStyle(element).borderLeftStyle,
    width: getComputedStyle(element).borderLeftWidth,
    height: element.getBoundingClientRect().height,
  }));
  assert(separator.style === "dashed" && separator.width === "1px" && separator.height > 200, JSON.stringify(separator));
  const sidebarPlacement = await page.locator(".sidebar").evaluate(element => ({
    position: getComputedStyle(element).position,
    top: element.getBoundingClientRect().top,
    bottom: element.getBoundingClientRect().bottom,
    pageBottom: document.querySelector(".shell").getBoundingClientRect().bottom,
    viewportHeight: innerHeight,
  }));
  assert.equal(sidebarPlacement.position, "sticky");
  assert(Math.abs(sidebarPlacement.top) < 1 && Math.abs(sidebarPlacement.bottom - sidebarPlacement.viewportHeight) < 1, JSON.stringify(sidebarPlacement));
  assert(sidebarPlacement.pageBottom > sidebarPlacement.viewportHeight, JSON.stringify(sidebarPlacement));
  await page.evaluate(() => scrollTo(0, document.documentElement.scrollHeight));
  await page.waitForTimeout(100);
  const stickyProfile = await page.locator(".sidebar").evaluate(element => ({
    top: element.getBoundingClientRect().top,
    bottom: element.getBoundingClientRect().bottom,
    profileBottom: element.querySelector(".sidebar-bottom").getBoundingClientRect().bottom,
    viewportHeight: innerHeight,
  }));
  assert(Math.abs(stickyProfile.top) < 1 && Math.abs(stickyProfile.bottom - stickyProfile.viewportHeight) < 1, JSON.stringify(stickyProfile));
  assert(stickyProfile.viewportHeight - stickyProfile.profileBottom <= 21, JSON.stringify(stickyProfile));
  await page.evaluate(() => scrollTo(0, 0));
  assert.equal(await page.locator('#search, #filter, [aria-label="Поиск задач"], [aria-label="Фильтр задач"]').count(), 0);
  assert.equal(await page.locator("article.task .points, article.task .recommend-label").count(), 0);
  assert.equal(await page.getByText("Пока никто не взял", { exact: true }).count(), 0);
  assert.equal(await page.locator("article.task .task-meta").filter({ hasText: "решений" }).count(), 0);
  const joinButton = page.locator("article.task [data-join]").first();
  assert.equal(await joinButton.evaluate(element => element.classList.contains("primary")), true);
  assert.equal(await joinButton.evaluate(element => getComputedStyle(element).backgroundColor), "rgb(189, 237, 133)");
  const mineCard = page.locator('article[data-task="1"]');
  assert.equal(await mineCard.evaluate(element => element.classList.contains("task-mine")), true);
  assert.equal(await mineCard.evaluate(element => getComputedStyle(element).borderColor), "rgb(189, 237, 133)");
  assert.equal(await page.locator('article[data-task="2"]').evaluate(element => element.classList.contains("task-mine")), false);
  const navigation = await page.locator(".nav [data-page]").evaluateAll(items => items.map(item => item.dataset.page));
  assert.deepEqual(navigation.slice(0, 2), ["board", "rating"]);
  await page.locator('.nav [data-page="rating"]').click();
  await page.getByRole("heading", { name: "Рейтинг", exact: true }).waitFor();
  assert.equal(await page.locator(".leaderboard-row").count(), 7);
  assert.equal(await page.locator(".leaderboard-row.rank-1").count(), 1);
  assert.equal(await page.locator(".leaderboard-row.rank-5").count(), 1);
  assert.equal(await page.locator(".leaderboard-head").innerText(), "№ П/П\nФАМИЛИЯ\nРЕШЕНО");
  await page.waitForFunction(() => getComputedStyle(document.querySelector("#content")).opacity === "1");
  await page.waitForTimeout(800);
  await page.screenshot({ path: "instance/rating-desktop.png", fullPage: true });
  await page.locator('.nav [data-page="board"]').click();
  const compact = await page.locator("article.task").first().boundingBox();
  assert(compact.width < 300 && compact.height < 320, JSON.stringify(compact));
  const assigned = await page.locator('article[data-task="1"] .task-card-team').evaluate(el => ({
    avatars: el.querySelectorAll(".avatar").length,
    overflow: el.scrollWidth - el.clientWidth,
  }));
  assert(assigned.avatars === 1 && assigned.overflow <= 0, JSON.stringify(assigned));
  const crowdedMembers = Array.from({length: 13}, (_, index) => ({
    id: 100 + index,
    name: `Участник ${index + 1}`,
  }));
  await page.route("**/api/board/1", async route => {
    const response = await route.fetch();
    const payload = await response.json();
    payload.tasks.find(task => task.id === 1).members = crowdedMembers;
    await route.fulfill({response, json: payload});
  });
  await page.locator('article[data-task="1"]').click();
  await page.locator("#modal .task-team-icons").waitFor();
  assert.equal(await page.locator("#modal .task-team-icons .avatar").count(), 10);
  assert.equal(await page.locator("#modal .task-team-more").innerText(), "+3");
  const crowdedLayout = await page.locator("#modal .task-workbar").evaluate(element => {
    const team = element.querySelector(".task-team-icons").getBoundingClientRect();
    const action = element.querySelector("button").getBoundingClientRect();
    return {teamHeight: team.height, gap: action.left - team.right, overflow: element.scrollWidth - element.clientWidth};
  });
  assert(crowdedLayout.teamHeight <= 48 && crowdedLayout.gap >= 15 && crowdedLayout.overflow <= 0, JSON.stringify(crowdedLayout));
  await page.waitForTimeout(300);
  await page.screenshot({path: "instance/task-team-desktop.png"});
  await page.getByRole("button", {name: "Закрыть", exact: true}).click();
  await page.evaluate(() => renderPage());
  assert.equal(await page.locator('article[data-task="1"] .task-card-team .avatar').count(), 9);
  assert.equal(await page.locator('article[data-task="1"] .task-card-team .task-team-more').innerText(), "+4");
  const cardTeamLayout = await page.locator('article[data-task="1"] .task-card-team').evaluate(element => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
    cardWidth: element.closest("article").clientWidth,
  }));
  assert(cardTeamLayout.scrollWidth <= cardTeamLayout.clientWidth, JSON.stringify(cardTeamLayout));
  await page.screenshot({path: "instance/task-card-team-desktop.png"});
  await page.unroute("**/api/board/1");
  await page.reload();
  await page.getByRole("heading", {name: "Доска задач", exact: true}).waitFor();
  await page.locator("[data-category=Web]").click();
  assert.equal(await page.locator("article.task").count(), 2);
  await page.locator('[data-category="Все"]').click();
  await page.locator(".nav [data-page=captain]").click();
  await page
    .getByRole("heading", { name: "Статистика участников" })
    .waitFor();
  assert.equal(await page.locator(".captain-table tbody tr").count(), 7);
  assert.equal(await page.locator(".captain-table tbody tr.member-idle").count(), 6);
  assert.equal(await page.locator(".captain-table tbody tr.member-help").count(), 1);
  assert.equal(await page.locator(".captain-table tbody tr.member-help .member-status").innerText(), "Нужна помощь");
  assert.equal(await page.locator(".captain-table tbody tr.member-idle .member-status").first().innerText(), "Сидит без дела");
  assert.equal(await page.locator(".captain-table tbody tr").last().getAttribute("data-member"), "1");
  assert.equal(await page.locator('.captain-table [data-member="2"] td').nth(4).innerText(), "0");
  await page.screenshot({ path: "instance/captain-desktop.png", fullPage: true });
  await page.locator(".nav [data-page=admin]").click();
  await page
    .getByRole("heading", { name: "Участники", exact: false })
    .waitFor();
  assert.equal(await page.getByRole("heading", { name: "Соревнования", exact: true }).count(), 0);
  assert.equal(await page.locator('.users-table [data-member="2"] .user-password').innerText(), accounts[0].password);
  await page.getByRole("button", { name: "Создать участников" }).click();
  await page.locator("#users-form [name=names]").fill("tester");
  await page.getByRole("button", { name: "Сгенерировать аккаунты" }).click();
  await page.getByRole("heading", { name: "Доступы созданы" }).waitFor();
  await page.getByRole("button", { name: "Закрыть", exact: true }).click();
  await page.locator(".nav [data-page=board]").click();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(() => getComputedStyle(document.querySelector("#content")).opacity === "1");
  await page.screenshot({ path: "instance/board-mobile.png", fullPage: true });
  assert(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
    "Mobile horizontal overflow",
  );
  const freeBefore = await page.locator('[data-status="free"] article.task').evaluateAll(cards => cards.map(card => Number(card.dataset.task)));
  assert(freeBefore.length > 1 && freeBefore[0] === 4, JSON.stringify(freeBefore));
  const firstFreeY = (await page.locator(`[data-status="free"] article[data-task="${freeBefore[0]}"]`).boundingBox()).y;
  const memberContext = await browser.newContext();
  const memberPage = await memberContext.newPage();
  memberPage.on("pageerror", (error) => errors.push(error.message));
  await memberPage.goto(process.env.TEST_URL || "http://127.0.0.1:5001");
  await memberPage.locator("[name=login]").fill(accounts[0].login);
  await memberPage.locator("[name=password]").fill(accounts[0].password);
  await memberPage.getByRole("button", { name: "Войти в штаб" }).click();
  await memberPage
    .locator("#password-form [name=current]")
    .fill(accounts[0].password);
  await memberPage
    .locator("#password-form [name=password]")
    .fill("member-new-password");
  await memberPage.getByRole("button", { name: "Сохранить и войти" }).click();
  await memberPage
    .getByRole("heading", { name: "Доска задач", exact: true })
    .waitFor();
  assert.equal(await memberPage.locator("[data-page=admin]").count(), 0);
  assert.equal(await memberPage.locator("[data-page=captain]").count(), 0);
  assert.equal(await memberPage.locator('[data-action="new-task"], [data-page="assistant"]').count(), 0);
  await memberPage.getByRole("button", { name: "Сменить пароль" }).click();
  await memberPage.locator("#change-password-form [name=current]").fill("member-new-password");
  await memberPage.locator("#change-password-form [name=password]").fill("short");
  await memberPage.locator("#change-password-form [name=confirmation]").fill("short");
  await memberPage.getByRole("button", { name: "Сохранить новый пароль" }).click();
  await memberPage.getByText("Пароль должен содержать не менее 8 символов", { exact: true }).waitFor();
  assert.equal(await memberPage.locator("#change-password-form [name=password]").getAttribute("aria-invalid"), "true");
  await memberPage.locator("#change-password-form [name=password]").fill("member-self-service-password");
  await memberPage.locator("#change-password-form [name=confirmation]").fill("member-self-service-password");
  await memberPage.getByRole("button", { name: "Сохранить новый пароль" }).click();
  await memberPage.getByText("Пароль изменён", { exact: true }).waitFor();
  const forbidden = await memberPage.request.get(
    (process.env.TEST_URL || "http://127.0.0.1:5001") + "/api/admin/stats/1",
  );
  assert.equal(forbidden.status(), 403);
  await memberPage.locator('article[data-task="4"] [data-join]').click();
  await page.locator('article[data-task="4"]').getByTitle("alice").waitFor();
  const freeAfter = await page.locator('[data-status="free"] article.task').evaluateAll(cards => cards.map(card => Number(card.dataset.task)));
  assert.deepEqual(freeAfter, freeBefore.slice(1));
  assert.equal(await page.locator('[data-status="working"] article[data-task="4"]').count(), 1);
  const shiftedY = (await page.locator(`[data-status="free"] article[data-task="${freeAfter[0]}"]`).boundingBox()).y;
  assert(Math.abs(shiftedY - firstFreeY) < 1, `${shiftedY} !== ${firstFreeY}`);
  await page.locator('article[data-task="4"] .avatar[title="alice"]').waitFor();
  await request("/tasks/10", { action: "help" });
  await page.locator('article[data-task="4"] [data-join]').click();
  await page.locator('article[data-task="4"] .avatar[title="captain"]').waitFor();
  assert.equal(await page.locator('article[data-task="4"] .task-card-team .avatar').count(), 2);
  await memberPage
    .getByRole("button", { name: "Выйти", exact: true })
    .first()
    .click();
  await memberPage.getByRole("heading", { name: "С возвращением" }).waitFor();
  await memberContext.close();
  const captainAccount = (await request("/admin/users", { names: ["Test captain"], role: "captain" }))[0];
  const captainContext = await browser.newContext();
  const captainPage = await captainContext.newPage();
  captainPage.on("pageerror", error => errors.push(error.message));
  const base = process.env.TEST_URL || "http://127.0.0.1:5001";
  const headers = { "X-Requested-With": "CTFBoard" };
  await captainPage.request.post(base + "/api/login", { data: captainAccount, headers });
  await captainPage.request.post(base + "/api/password", { data: { current: captainAccount.password, password: "captain-new-password" }, headers });
  await captainPage.goto(base);
  await captainPage.getByRole("heading", { name: "Доска задач", exact: true }).waitFor();
  assert.equal(await captainPage.locator('[data-page="admin"], [data-page="captain"], [data-action="new-task"]').count(), 0);
  const noCreate = await captainPage.request.post(base + "/api/tasks", { data: { title: "Forbidden", competition_id: 1 }, headers });
  assert.equal(noCreate.status(), 403);
  await captainContext.close();
  await page.setViewportSize({ width: 1512, height: 982 });
  await page.locator(".nav [data-page=admin]").click();
  await page.getByRole("heading", { name: "Участники", exact: false }).waitFor();
  assert.equal(await page.locator('.users-table [data-member="2"] .user-password').innerText(), "member-self-service-password");
  await page.getByRole("button", { name: "Настроить источник" }).click();
  await page
    .locator("#source-form [name=url]")
    .fill(process.env.TEST_SOURCE_URL);
  await page.locator("#source-form [name=enabled]").check();
  await page.locator("#source-form [name=auth_method]").selectOption("token");
  await page.locator("#source-form [name=source_token]").fill("browser-ctfd-token");
  await page.screenshot({path:"instance/parser-desktop.png"});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:"instance/parser-mobile.png"});
  const mobileOverflow = await page.evaluate(() => ({
    viewport: innerWidth,
    page: document.documentElement.scrollWidth,
    widest: [...document.querySelectorAll("*")]
      .map((element) => ({tag: element.tagName, id: element.id, cls: element.className, right: element.getBoundingClientRect().right, width: element.getBoundingClientRect().width}))
      .filter((item) => item.right > innerWidth + 1)
      .sort((a, b) => b.right - a.right)
      .slice(0, 3),
  }));
  assert.equal(mobileOverflow.page > mobileOverflow.viewport, false, JSON.stringify(mobileOverflow));
  await page.getByRole("button", { name: "Проверить и подключить" }).click();
  await page.locator("#source-status").getByText(/CTFD/).waitFor();
  await page.setViewportSize({width: 1512, height: 982});
  await page.locator(".nav [data-page=board]").click();
  await page
    .getByRole("heading", { name: "Automatically imported", exact: true })
    .waitFor();
  await request("/tasks/1", {action: "leave"});
  await request("/tasks/10", {action: "leave"});
  await page.reload();
  await page.getByRole("heading", { name: "Automatically imported", exact: true }).waitFor();
  const importedCard = page.locator("article.task").filter({has: page.getByRole("heading", {name: "Automatically imported", exact: true})});
  await importedCard.getByRole("button", {name: "Присоединиться"}).click();
  await importedCard.click();
  await page.locator("#task-container").getByText("Остановлен", {exact: true}).waitFor();
  await page.locator("#task-container").getByRole("button", {name: "Запустить контейнер"}).click();
  await page.locator("#task-container").getByText("Запускается", {exact: true}).waitFor();
  await page.locator("#task-container").getByRole("link", {name: "https://instance.tasks.example"}).waitFor();
  assert.equal(await page.locator("#task-container").getByText("Работает", {exact: true}).count(), 1);
  await page.screenshot({path: "instance/container-desktop.png"});
  await page.setViewportSize({width: 390, height: 844});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({path: "instance/container-mobile.png"});
  assert.deepEqual(errors, []);
  await browser.close();
  console.log(
    "Browser workflows passed; desktop/mobile screenshots saved in instance/.",
  );
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
