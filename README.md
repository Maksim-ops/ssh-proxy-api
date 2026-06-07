# core-api

`core-api` — локально запущенный FastAPI-сервис, который принимает команды по HTTP, проверяет их по policy, выполняет на удалённом сервере через SSH и стримит stdout/stderr по websocket.

## Схема

```text
pctl / curl / service X
        |
        | POST /api/v1/exec
        v
+-----------------------------+
| core-api                    |
| - token auth                |
| - policy engine             |
| - MySQL metadata/audit      |
| - CommandStream             |
| - websocket /ws             |
| - AsyncSSH manager          |
+-------------+---------------+
              |
              | SSH
              v
+-----------------------------+
| remote server: lifeorient   |
+-----------------------------+
```

Поток выполнения:

```text
SSH stdout/stderr
      |
   AsyncSSH
      |
 CommandStream
      |
      +--> history (last N lines)
      +--> logfile in volume
      +--> CLI subscriber (pctl)
      +--> WebSocket subscriber (/ws)
```

## Что умеет приложение

- принимать команды через `POST /api/v1/exec`
- проверять команды по deny-by-default policy
- выполнять разрешённые команды на `lifeorient` по SSH
- стримить `stdout`/`stderr` через websocket
- хранить `jobs`, `audit`, `servers`, `command_streams` в локальной MySQL
- писать stdout/stderr и audit в volume на локальной машине
- отменять long-running команды через `POST /api/v1/cancel`
- отдавать `GET /api/v1/jobs`, `GET /api/v1/audit`, `GET /api/v1/running`
- давать CRUD для `users`, `proxies`, `servers`, `actions`, `tokens`

## Как работает SSH-соединение

`core-api` не открывает новое SSH-соединение на каждую команду.

- при первой команде создаётся SSH connection к `lifeorient`
- следующие команды переиспользуют это соединение
- после последней команды соединение держится idle несколько минут
- текущий idle timeout: `300` секунд
- затем соединение закрывается автоматически
- при `cancel` и аварийных ситуациях connection может быть принудительно reset

Настройка задаётся в server config:

```yaml
servers:
  lifeorient:
    sshHost: lifeorient
    commandTimeoutSeconds: 120
    idleDisconnectSeconds: 300
```

## Локальный запуск

Поднять всё локально:

```bash
bash scripts/up.sh
```

Это делает:

- прогон тестов
- `docker compose up -d --build mysql core-api adminer`
- установку launcher в `/usr/local/bin/pctl`

Проверка health:

```bash
curl -sS http://127.0.0.1:8080/health
```

Adminer:

```text
http://127.0.0.1:8088
```

## Локальные сервисы и volume

В `docker-compose.yml`:

- MySQL data: `./mysql-data`
- app logs: `./api-logs`

Логи команд лежат так:

```text
./api-logs/jobs/<server>/<request_id>/stdout.log
./api-logs/jobs/<server>/<request_id>/stderr.log
```

Audit JSONL:

```text
./api-logs/audit/audit.jsonl
```

## Авторизация

Теперь основной auth-flow для UI такой:

1. UI вызывает `POST /api/v1/auth/token` c `email`.
2. Если пользователь с таким email есть в таблице `users`, API возвращает Bearer token.
3. UI использует этот token в `Authorization: Bearer <token>` для HTTP API и websocket.
4. UI может проверить текущего пользователя через `GET /api/v1/auth/me`.
5. UI может инвалидировать выданный токен через `POST /api/v1/auth/logout`.

Пример получения токена по email:

```bash
curl -sS -X POST   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/auth/token   -d '{
    "email": "maksim.nikitin@flant.com"
  }'
```

Пример ответа:

```json
{
  "ok": true,
  "token_type": "Bearer",
  "access_token": "<issued-token>",
  "user": {
    "id": 1,
    "username": "maksim.nikitin",
    "email": "maksim.nikitin@flant.com",
    "role": "admin"
  }
}
```

Проверить текущего пользователя:

```bash
curl -sS   -H 'Authorization: Bearer <issued-token>'   http://127.0.0.1:8080/api/v1/auth/me
```

Разлогиниться и инвалидировать текущий выданный токен:

```bash
curl -sS -X POST   -H 'Authorization: Bearer <issued-token>'   http://127.0.0.1:8080/api/v1/auth/logout
```

Статический token из `PCTL_API_TOKEN` всё ещё поддерживается как bootstrap/fallback для CLI и локальной отладки:

```text
dev-local-token-change-me
```

## Share link и браузер

После `POST /api/v1/exec` сервис возвращает:

- `ws_path` — websocket для авторизованного клиента
- `share_ws_path` — websocket с `share_token`, который можно передать другому человеку

Пример `share_ws_path`:

```text
/ws?stream_id=<id>&share_token=<token>
```

Важно:

- это именно websocket endpoint, а не HTML-страница
- открыть его в адресной строке браузера как обычную ссылку недостаточно
- для просмотра нужен клиент, который умеет подключаться к websocket и рисовать поток на странице
- таким клиентом может быть UI, отдельная HTML-страница с JavaScript или даже ручное подключение из DevTools

## CRUD API

CRUD вынесен в отдельные пакеты:

- `app/api/crud/routes/`
- `app/api/crud/schemas/`

Поддерживаемые сущности:

- `users`
- `proxies`
- `servers`
- `actions`
- `tokens`

Схема маршрутов для каждой сущности одинаковая:

- `GET /api/v1/<entity>`
- `GET /api/v1/<entity>/{id}`
- `POST /api/v1/<entity>`
- `PATCH /api/v1/<entity>/{id}`
- `DELETE /api/v1/<entity>/{id}`

Примеры:

Создать пользователя:

```bash
curl -sS -X POST   -H 'Authorization: Bearer dev-local-token-change-me'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/users   -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "role": "admin"
  }'
```

Получить список серверов:

```bash
curl -sS   -H 'Authorization: Bearer dev-local-token-change-me'   http://127.0.0.1:8080/api/v1/servers
```

Обновить proxy:

```bash
curl -sS -X PATCH   -H 'Authorization: Bearer dev-local-token-change-me'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/proxies/1   -d '{
    "proxy": "bastion-1"
  }'
```

Создать token:

```bash
curl -sS -X POST   -H 'Authorization: Bearer dev-local-token-change-me'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/tokens   -d '{
    "name": "cli-user-1",
    "token": "super-secret-token",
    "enabled": true
  }'
```

## SSH connection status

SSH-соединение к серверу не закрывается сразу после каждой команды.

Сейчас поведение такое:

- при первой команде создаётся SSH connection
- следующие команды на тот же сервер переиспользуют его
- после завершения последней команды соединение держится idle ещё `idleDisconnectSeconds`
- по умолчанию это `300` секунд, то есть 5 минут
- если в этот период приходит новая команда, idle-close отменяется и соединение используется повторно

Проверить текущее состояние SSH-соединений:

```bash
pctl ssh-status
```

Или через curl:

```bash
curl -sS \
  -H 'Authorization: Bearer dev-local-token-change-me' \
  http://127.0.0.1:8080/api/v1/ssh/status
```

Пример ответа:

```json
{
  "ok": true,
  "connections": [
    {
      "server": "lifeorient",
      "ssh_host": "lifeorient",
      "connected": true,
      "active_commands": 0,
      "connected_at": "2026-06-06T02:20:00+00:00",
      "last_used_at": "2026-06-06T02:21:15+00:00",
      "idle_disconnect_at": "2026-06-06T02:26:15+00:00",
      "idle_disconnect_in_seconds": 297,
      "idle_disconnect_seconds": 300,
      "command_timeout_seconds": 120
    }
  ]
}
```

Полезный сценарий проверки reuse:

1. Выполнить любую команду через `pctl exec` или `POST /api/v1/exec`.
2. Сразу вызвать `GET /api/v1/ssh/status`.
3. Убедиться, что `connected=true`, а `idle_disconnect_in_seconds` уменьшается.
4. Запустить ещё одну команду до истечения idle-таймера и убедиться, что соединение не создаётся заново, а `last_used_at` обновляется.

## Policy и сервер

Сервер для выполнения указывается явно:

```json
{
  "server": "lifeorient"
}
```

В `pctl` сервер выбирается по приоритету:

1. `--server`
2. `PCTL_SERVER`
3. `pctl switch <server>`
4. `PCTL_DEFAULT_SSH_HOST`
5. `PCTL_DEFAULT_SERVER`

## Тестовые curl-запросы

Выполнить `date`:

```bash
curl -sS -X POST   -H 'Authorization: Bearer dev-local-token-change-me'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/exec   -d '{
    "request_id": "test-date-1",
    "server": "lifeorient",
    "argv": ["date"],
    "client_type": "CLI"
  }'
```

Проверить, можно ли команду выполнить:

```bash
curl -sS -X POST   -H 'Authorization: Bearer dev-local-token-change-me'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/can-i   -d '{
    "server": "lifeorient",
    "argv": ["tail", "-f", "/root/test.txt"]
  }'
```

Запустить `sleep 100`:

```bash
curl -sS -X POST   -H 'Authorization: Bearer dev-local-token-change-me'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/exec   -d '{
    "request_id": "sleep-test-1",
    "server": "lifeorient",
    "argv": ["sleep", "100"],
    "client_type": "CLI"
  }'
```

Отменить команду:

```bash
curl -sS -X POST   -H 'Authorization: Bearer dev-local-token-change-me'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/cancel   -d '{"request_id":"sleep-test-1"}'
```

Проверить jobs:

```bash
curl -sS   -H 'Authorization: Bearer dev-local-token-change-me'   http://127.0.0.1:8080/api/v1/jobs
```

Проверить audit:

```bash
curl -sS   -H 'Authorization: Bearer dev-local-token-change-me'   http://127.0.0.1:8080/api/v1/audit
```

## Тестовые команды pctl

Выполнить `date`:

```bash
PCTL_API_TOKEN=dev-local-token-change-me pctl --server lifeorient exec -- date
```
