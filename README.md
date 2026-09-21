# Flagroom

## Русский

Flagroom помогает CTF-команде распределять задачи на Kanban-доске. Участники видят, кто работает над задачей, обсуждают её в отдельном чате и отправляют флаги. Администратор (капитан команды) управляет участниками и видит статистику занятости и решений.

### Запуск

Требуется Python 3.12+.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp -n .env.example .env
```

Для новой базы задайте в локальном `.env` `ADMIN_LOGIN`, `ADMIN_NAME` и `ADMIN_PASSWORD_HASH`. Получить хеш пароля без записи самого пароля в историю команд можно так:

```bash
.venv/bin/python -c 'import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass.getpass("Пароль администратора: ")))'
```

Без `ADMIN_PASSWORD_HASH` администратор не создаётся. Если вы восстанавливаете существующую базу, сохраните вместе с ней каталог `instance/` и локальный `.env`.

```bash
./run.sh
```

Откройте `http://127.0.0.1:5000`. Для публичного размещения используйте HTTPS и установите `COOKIE_SECURE=1`.

## English

Flagroom helps a CTF team coordinate challenges on a Kanban board. Teammates can see who is working on each challenge, discuss it in a dedicated chat, and submit flags. The administrator (team captain) manages members and views workload and solve statistics.

### Run

Python 3.12+ is required.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp -n .env.example .env
```

For a fresh database, set `ADMIN_LOGIN`, `ADMIN_NAME`, and `ADMIN_PASSWORD_HASH` in your local `.env`. Generate a Werkzeug password hash without putting the password in your shell history:

```bash
.venv/bin/python -c 'import getpass; from werkzeug.security import generate_password_hash; print(generate_password_hash(getpass.getpass("Admin password: ")))'
```

No administrator is created without `ADMIN_PASSWORD_HASH`. To restore an existing database, keep its `instance/` directory and local `.env` together.

```bash
./run.sh
```

Open `http://127.0.0.1:5000`. For public deployment, use HTTPS and set `COOKIE_SECURE=1`.
