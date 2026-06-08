# core-api

`core-api` — FastAPI-сервис для выполнения команд по HTTP, проверки по policy, запуска на удалённых серверах по SSH и стриминга stdout/stderr по websocket.

## Схема

```text
UI / curl / pctl
        |
        | HTTP API + WebSocket
        v
+-----------------------------+
| core-api                    |
| - password auth             |
| - opaque user sessions      |
| - role / permission model   |
| - team-based visibility     |
| - policy engine             |
| - MySQL metadata / audit    |
| - websocket /ws             |
| - AsyncSSH manager          |
+-------------+---------------+
              |
              | SSH
              v
+-----------------------------+
| remote servers              |
+-----------------------------+
```

## Что умеет приложение

- выполнять разрешённые команды через `POST /api/v1/exec`
- стримить выполнение через websocket `/ws`
- хранить `jobs`, `job_logs`, `command_streams`, `audit_events`, `teams`, `users`, `user_sessions`
- вести audit auth/exec событий
- ограничивать видимость серверов и command sessions по команде пользователя
- управлять users / teams / servers / proxies / tokens через CRUD API для superadmin

## Auth и session model

Локальный login больше не выдаёт токен только по email.

Теперь flow такой:

1. UI вызывает `POST /api/v1/auth/token` с `email` и `password`.
2. API проверяет локальный password hash и rate limit.
3. Если credentials валидны, создаётся запись в `user_sessions`.
4. Клиент получает opaque Bearer token, который хранится в БД только в виде hash.
5. У сессии есть TTL (`expires_at`), `last_used_at`, `revoked_at`, `revoked_reason`, `ip_address`, `user_agent`.

### Что реализовано для production-like auth

- password-based factor владения для локальных запусков
- отдельная таблица `user_sessions`
- сроки жизни токена / session TTL
- revoke текущей сессии: `POST /api/v1/auth/logout`
- revoke всех сессий пользователя: `POST /api/v1/auth/logout-all`
- revoke любой auth session superadmin'ом: `POST /api/v1/auth/sessions/{session_uid}/revoke`
- rotation текущей сессии: `POST /api/v1/auth/rotate`
- rotation после sensitive action: `POST /api/v1/auth/password`
- rate limit на auth endpoints
- защита от user enumeration: при bad email/password возвращается общий `invalid_credentials`
- аудит событий: `failed_login`, `logout`, `token_revoked`, `suspicious_auth_attempt`

### Ограничения текущей локальной реализации

- transport пока HTTP, не HTTPS
- auth rate limit in-memory и привязан к одному инстансу приложения
- OIDC / OTP пока не подключены, но локальный session model уже совместим по структуре с будущим внешним login provider

## Роли, permissions и команды

Поддерживаются роли:

- `superadmin`
- `engineer`
- `tl`
- `pm`

`superadmin` видит и управляет всем.

Остальные роли ограничены своей командой:

- пользователь привязан к `team_id`
- сервер привязан к `team_id`
- пользователь команды видит только свои серверы
- command sessions и running commands тоже фильтруются по серверам команды

### Таблицы, связанные с access model

- `teams`
- `users.team_id`
- `servers.team_id`
- `user_sessions`

## Переменные окружения

Основные env для локального auth:

```text
PCTL_SUPERADMIN_EMAIL=superadmin@local
PCTL_SUPERADMIN_USERNAME=superadmin
PCTL_SUPERADMIN_PASSWORD=superadmin-change-me
PCTL_AUTH_ACCESS_TTL_MINUTES=480
PCTL_AUTH_RATE_LIMIT_WINDOW_SECONDS=300
PCTL_AUTH_RATE_LIMIT_MAX_ATTEMPTS=10
PCTL_AUTH_SUSPICIOUS_THRESHOLD=5
PCTL_AUTH_PASSWORD_ITERATIONS=600000
PCTL_AUTH_PASSWORD_PEPPER=
```

`superadmin` создаётся/обновляется на старте приложения из этих env.

## Docker Compose

В `docker-compose.yml` уже нужно задавать пароль superadmin через env `core-api` сервиса.

Минимальный пример:

```yaml
environment:
  PCTL_SUPERADMIN_EMAIL: superadmin@local
  PCTL_SUPERADMIN_USERNAME: superadmin
  PCTL_SUPERADMIN_PASSWORD: change-me-now
```

## Локальный запуск

```bash
bash scripts/up.sh
```

Health:

```bash
curl -sS http://127.0.0.1:8080/health
```

UI:

```text
http://127.0.0.1:8081
```

Adminer:

```text
http://127.0.0.1:8088
```

## Примеры auth API

### Логин по email/password

```bash
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/api/v1/auth/token \
  -d '{
    "email": "superadmin@local",
    "password": "change-me-now"
  }'
```

Пример ответа:

```json
{
  "ok": true,
  "token_type": "Bearer",
  "access_token": "<opaque-session-token>",
  "expires_at": "2026-06-07T20:00:00+00:00",
  "session": {
    "id": 7,
    "session_uid": "8a0f...",
    "user_id": 1,
    "created_at": "2026-06-07T12:00:00+00:00",
    "expires_at": "2026-06-07T20:00:00+00:00",
    "last_used_at": "2026-06-07T12:00:00+00:00",
    "revoked_at": null,
    "revoked_reason": null,
    "ip_address": "127.0.0.1",
    "user_agent": "Mozilla/..."
  },
  "user": {
    "id": 1,
    "username": "superadmin",
    "email": "superadmin@local",
    "role": "superadmin",
    "team_id": null,
    "team_name": null,
    "permissions": [
      "audit:read_all",
      "auth:revoke_any_session",
      "auth:view_all_sessions",
      "jobs:read_all",
      "servers:manage",
      "servers:read_all",
      "teams:manage",
      "teams:read_all",
      "users:manage"
    ]
  }
}
```

### Проверить текущего пользователя

```bash
curl -sS \
  -H 'Authorization: Bearer <token>' \
  http://127.0.0.1:8080/api/v1/auth/me
```

### Разлогинить только текущую сессию

```bash
curl -sS -X POST \
  -H 'Authorization: Bearer <token>' \
  http://127.0.0.1:8080/api/v1/auth/logout
```

### Разлогинить все свои сессии

```bash
curl -sS -X POST \
  -H 'Authorization: Bearer <token>' \
  http://127.0.0.1:8080/api/v1/auth/logout-all
```

### Посмотреть auth sessions

```bash
curl -sS \
  -H 'Authorization: Bearer <token>' \
  http://127.0.0.1:8080/api/v1/auth/sessions
```

### Сменить пароль и сразу ротировать текущую сессию

```bash
curl -sS -X POST \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/api/v1/auth/password \
  -d '{
    "current_password": "change-me-now",
    "new_password": "even-stronger-password"
  }'
```

## CRUD API

Superadmin-only CRUD:

- `GET/POST/PATCH/DELETE /api/v1/users`
- `GET/POST/PATCH/DELETE /api/v1/teams`
- `GET/POST/PATCH/DELETE /api/v1/admin/servers`
- `GET/POST/PATCH/DELETE /api/v1/proxies`
- `GET/POST/PATCH/DELETE /api/v1/actions`
- `GET/POST/PATCH/DELETE /api/v1/tokens`

При создании/обновлении пользователя можно передать локальный password:

```bash
curl -sS -X POST \
  -H 'Authorization: Bearer <superadmin-token>' \
  -H 'Content-Type: application/json' \
  http://127.0.0.1:8080/api/v1/users \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "role": "engineer",
    "team_id": 1,
    "password": "alice-local-password",
    "is_active": true
  }'
```

Если superadmin меняет пользователю password, его активные auth sessions автоматически отзываются.

## Server и session visibility

- `GET /api/v1/servers` — scoped list серверов для текущего пользователя
- `GET /api/v1/sessions` — scoped history command sessions
- `GET /api/v1/sessions/{request_id}` — scoped detail + stdout/stderr
- `DELETE /api/v1/sessions/{request_id}` — soft-delete из History UI, запись остаётся в БД
- `GET /api/v1/running` — scoped running commands
- `GET /api/v1/ssh/status` — scoped SSH status

## UI

Фронтенд находится в соседнем репозитории `../ai-proxy-web`.

Сейчас есть два основных view:

- `superadmin` view: все команды, все серверы, history, auth sessions, audit
- `engineer` view: только серверы своей команды и history своей команды

История в UI изменена:

- слева панели с датой открытия/закрытия
- справа описание и лог выбранной сессии
- вместо `completed 0` есть кнопка удаления сессии из History
- `Open in Stream` убран из History и остался только в `Stream`

## Share link и websocket

После `POST /api/v1/exec` сервис возвращает:

- `ws_path` — websocket для авторизованного клиента
- `share_ws_path` — websocket с `share_token`

Пример:

```text
/ws?stream_id=<id>&share_token=<token>
```

`share_token` даёт доступ только к конкретному stream. Обычный Bearer token дополнительно проверяется по role/team scope.

## Проверка изменений

Проверялось так:

```bash
docker compose run --rm pctl-tests
cd ../ai-proxy-web && npm run build
```
