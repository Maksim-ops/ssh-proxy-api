# pctl-proxy MVP

`pctl-proxy` — это MVP HTTP command gateway для выполнения разрешённых команд на удалённых Linux-серверах через SSH.

На текущем этапе сервис:

- запускается в Docker;
- принимает REST API-запросы;
- проверяет Bearer token;
- проверяет команду по YAML-политикам;
- держит persistent SSH-соединение через `asyncssh`;
- выполняет команду на удалённом сервере;
- возвращает JSON с `stdout`, `stderr`, `exit_code`.

---

## 1. Общая схема

```text
curl / future pctl wrapper / service X
        |
        | HTTP POST + JSON
        v
+-----------------------------+
| pctl-proxy                  |
| FastAPI service in Docker   |
|                             |
| - token auth                |
| - YAML config               |
| - command policy check      |
| - SSH connection manager    |
| - asyncssh                  |
+-------------+---------------+
              |
              | persistent SSH connection
              v
+-----------------------------+
| Remote Linux server S       |
|                             |
| - обычный Linux server      |
| - Kubernetes master later   |
| - kubectl/kubeconfig later  |
+-----------------------------+
```

На текущем MVP клиентом выступает `curl`.

В будущем вместо `curl` предполагается CLI-wrapper:

```bash
pctl --server prod-master-1 -- kubectl get pods -n default
```

который будет преобразовывать команду в HTTP POST-запрос к `pctl-proxy`.

---

## 2. Как работает proxy

При запросе:

```http
POST /api/v1/exec
Authorization: Bearer <token>
Content-Type: application/json

{
  "server": "lifeorient",
  "argv": ["df", "-h"]
}
```

`pctl-proxy` выполняет шаги:

1. Проверяет Bearer token.
2. Ищет сервер `lifeorient` в YAML-конфиге.
3. Получает SSH alias из настройки `sshHost`.
4. Загружает политики:
   - `globalPolicies`;
   - политики конкретного сервера.
5. Проверяет команду по deny-by-default принципу.
6. Если команда запрещена — возвращает HTTP `403`.
7. Если команда разрешена:
   - безопасно собирает remote command из `argv`;
   - использует существующее SSH-соединение или открывает новое;
   - выполняет команду через SSH exec;
   - возвращает результат в JSON.

---

## 3. Важная архитектурная идея

Команды передаются не строкой:

```json
{
  "command": "df -h"
}
```

а массивом аргументов:

```json
{
  "argv": ["df", "-h"]
}
```

Это нужно, чтобы proxy мог безопаснее проверять команду политиками.

Удалённая команда всё равно отправляется на сервер в виде строки, но каждый аргумент экранируется через `shlex.quote`.

Например:

```json
{
  "argv": ["ls", "/tmp/test; rm -rf /"]
}
```

будет преобразовано не в:

```bash
ls /tmp/test; rm -rf /
```

а примерно в:

```bash
ls '/tmp/test; rm -rf /'
```

---

## 4. Текущая структура проекта

Примерная структура:

```text
.
├── app/
│   └── main.py
├── config/
│   └── config.yml
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

SSH-файлы монтируются отдельно, например:

```text
/home/maksim/.ssh_proxy
├── config
├── known_hosts
├── lifeorient
└── lifeorient.pub
```

---

## 5. Docker Compose

Пример `docker-compose.yml`:

```yaml
services:
  pctl-proxy:
    build: .
    container_name: pctl-proxy
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - /home/maksim/.ssh_proxy:/home/appuser/.ssh:ro
      - ./config:/etc/pctl:ro
    environment:
      - PCTL_CONFIG=/etc/pctl/config.yml
      - PCTL_API_TOKEN=dev-local-token-change-me
      - PCTL_SSH_CONFIG=/home/appuser/.ssh/config
      - PCTL_SSH_KNOWN_HOSTS=/home/appuser/.ssh/known_hosts
    restart: unless-stopped
```

Важно:

```yaml
ports:
  - "127.0.0.1:8080:8080"
```

Это означает, что API доступен только локально с машины, на которой запущен контейнер.

---

## 6. SSH config

Пример `/home/maksim/.ssh_proxy/config`:

```sshconfig
Host lifeorient
    HostName 84.54.28.170
    User root
    IdentityFile /home/appuser/.ssh/lifeorient
    IdentitiesOnly yes
    ServerAliveInterval 30
    ServerAliveCountMax 3
```

Важно: `IdentityFile` должен указывать путь **внутри контейнера**:

```sshconfig
IdentityFile /home/appuser/.ssh/lifeorient
```

Не путь на хостовой машине:

```sshconfig
IdentityFile /home/maksim/.ssh/lifeorient
```

---

## 7. known_hosts

Контейнер должен заранее доверять SSH host key сервера.

Пример:

```bash
ssh-keyscan -H 84.54.28.170 > /home/maksim/.ssh_proxy/known_hosts
```

Права:

```bash
chmod 700 /home/maksim/.ssh_proxy
chmod 600 /home/maksim/.ssh_proxy/config
chmod 400 /home/maksim/.ssh_proxy/lifeorient
chmod 644 /home/maksim/.ssh_proxy/known_hosts
```

---

## 8. YAML-конфиг политик

Пример `config/config.yml`:

```yaml
globalPolicies:
  - name: allow-df-h
    command: df
    allowedArgv:
      - ["-h"]

  - name: allow-uptime
    command: uptime
    allowedArgv:
      - []

  - name: allow-whoami
    command: whoami
    allowedArgv:
      - []

servers:
  lifeorient:
    sshHost: lifeorient
    commandTimeoutSeconds: 60
    policies:
      - name: allow-ls-paths
        command: ls
        allowedFlags:
          - "-l"
          - "-a"
          - "-h"
          - "-la"
          - "-al"
          - "-lh"
          - "-hl"
          - "-lah"
          - "-lha"
          - "-alh"
          - "-ahl"
        flagsPosition: anywhere
        pathArgs:
          min: 0
          max: 2
          allowAbsolute: true
          allowRelative: true
          allowGlobs: false
          allowParentTraversal: false
          denyPrefixes:
            - "/root/.ssh"
            - "/proc"
            - "/sys"
            - "/dev"
          denyRegex:
            - "^/etc/shadow$"
```

---

## 9. Типы политик

### 9.1 `allowedArgv`

Используется для точного совпадения аргументов.

Пример:

```yaml
- name: allow-df-h
  command: df
  allowedArgv:
    - ["-h"]
```

Разрешит:

```bash
df -h
```

Запретит:

```bash
df
df -i
df -h /
```

---

### 9.2 `allowedFlags` + `pathArgs`

Используется для команд, где есть флаги и пути.

Пример:

```yaml
- name: allow-ls-paths
  command: ls
  allowedFlags:
    - "-la"
    - "-lh"
  flagsPosition: anywhere
  pathArgs:
    min: 0
    max: 2
    allowAbsolute: true
    allowRelative: true
    allowGlobs: false
    allowParentTraversal: false
    denyPrefixes:
      - "/root/.ssh"
```

Разрешит:

```bash
ls
ls -la
ls /tmp
ls -la /tmp
ls /tmp -la
```

Запретит:

```bash
ls -R /
ls /root/.ssh
ls /*
```

---

## 10. `flagsPosition`

Поле `flagsPosition` управляет положением флагов.

### `anywhere`

```yaml
flagsPosition: anywhere
```

Разрешает:

```bash
ls -la /tmp
ls /tmp -la
```

### `beforePaths`

```yaml
flagsPosition: beforePaths
```

Разрешает:

```bash
ls -la /tmp
```

Запрещает:

```bash
ls /tmp -la
```

---

## 11. `pathArgs`

Пример:

```yaml
pathArgs:
  min: 0
  max: 2
  allowAbsolute: true
  allowRelative: true
  allowGlobs: false
  allowParentTraversal: false
  allowPrefixes:
    - "/tmp"
    - "/var/log"
  denyPrefixes:
    - "/root/.ssh"
  allowRegex:
    - "^/tmp(/.*)?$"
  denyRegex:
    - "^/etc/shadow$"
```

Поля:

| Поле | Описание |
|---|---|
| `min` | минимальное количество path-аргументов |
| `max` | максимальное количество path-аргументов |
| `allowAbsolute` | разрешены ли абсолютные пути |
| `allowRelative` | разрешены ли относительные пути |
| `allowGlobs` | разрешены ли glob-символы `*`, `?`, `[]`, `{}` |
| `allowParentTraversal` | разрешён ли `..` в пути |
| `allowPrefixes` | список разрешённых префиксов |
| `denyPrefixes` | список запрещённых префиксов |
| `allowRegex` | список regex-правил, под которые должен попасть путь |
| `denyRegex` | список regex-правил, которые запрещают путь |

`denyPrefixes` и `denyRegex` имеют приоритет над allow-правилами.

Если `allowRegex` и `allowPrefixes` не заданы, путь считается разрешённым, если он не попал под deny-правила и прошёл остальные проверки.

---

## 12. Глобальные и серверные политики

### Глобальные политики

```yaml
globalPolicies:
  - name: allow-df-h
    command: df
    allowedArgv:
      - ["-h"]
```

Применяются ко всем серверам.

### Серверные политики

```yaml
servers:
  lifeorient:
    policies:
      - name: allow-ls-paths
        command: ls
        ...
```

Применяются только к конкретному серверу.

### Отключение всех глобальных политик для сервера

```yaml
servers:
  lifeorient:
    disableGlobalPolicies: true
```

### Отключение отдельных глобальных политик

```yaml
servers:
  lifeorient:
    disabledGlobalPolicies:
      - allow-df-h
```

---

## 13. Запуск

Сборка и запуск:

```bash
docker compose up --build
```

В фоне:

```bash
docker compose up --build -d
```

Остановить:

```bash
docker compose down
```

Посмотреть логи:

```bash
docker logs -f pctl-proxy
```

---

## 14. Проверка health

`/health` не требует токена.

```bash
curl -s http://127.0.0.1:8080/health | jq
```

Пример ответа:

```json
{
  "status": "ok",
  "config": "/etc/pctl/config.yml",
  "servers": [
    "lifeorient"
  ],
  "globalPolicies": [
    "allow-df-h",
    "allow-uptime",
    "allow-whoami"
  ],
  "auth": "enabled"
}
```

---

## 15. Токен

Задаётся через переменную окружения:

```yaml
environment:
  - PCTL_API_TOKEN=dev-local-token-change-me
```

Для запросов:

```bash
TOKEN="dev-local-token-change-me"
```

Header:

```http
Authorization: Bearer dev-local-token-change-me
```

---

## 16. SSH connect

```bash
curl -s -X POST http://127.0.0.1:8080/ssh/connect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient"}' | jq
```

Пример ответа:

```json
{
  "ok": true,
  "server": "lifeorient",
  "ssh_host": "lifeorient",
  "status": "connected"
}
```

---

## 17. SSH status

```bash
curl -s "http://127.0.0.1:8080/ssh/status?server=lifeorient" \
  -H "Authorization: Bearer $TOKEN" | jq
```

Пример ответа:

```json
{
  "server": "lifeorient",
  "ssh_host": "lifeorient",
  "connected": true
}
```

---

## 18. SSH disconnect

```bash
curl -s -X POST http://127.0.0.1:8080/ssh/disconnect \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient"}' | jq
```

Пример ответа:

```json
{
  "ok": true,
  "server": "lifeorient",
  "ssh_host": "lifeorient",
  "status": "disconnected"
}
```

---

## 19. Выполнение команды

Endpoint:

```http
POST /api/v1/exec
```

Пример:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["df","-h"]}' | jq
```

Пример ответа:

```json
{
  "ok": true,
  "error": null,
  "message": null,
  "request_id": "9a7302d6-1f00-4b47-bc81-d098ed5366ea",
  "server": "lifeorient",
  "argv": [
    "df",
    "-h"
  ],
  "remote_command": "df -h",
  "stdout": "Filesystem      Size  Used Avail Use% Mounted on\n...",
  "stderr": "",
  "exit_code": 0,
  "duration_ms": 69,
  "policy": "allow-df-h"
}
```

---

## 20. Вывести только stdout

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["df","-h"]}' | jq -r .stdout
```

---

## 21. Примеры разрешённых запросов

### `df -h`

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["df","-h"]}' | jq
```

### `uptime`

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["uptime"]}' | jq
```

### `whoami`

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["whoami"]}' | jq
```

### `ls -la /tmp`

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["ls","-la","/tmp"]}' | jq
```

### `ls /tmp -la`

Если для политики задано:

```yaml
flagsPosition: anywhere
```

то такой формат тоже разрешён:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["ls","/tmp","-la"]}' | jq
```

---

## 22. Примеры запрещённых запросов

### Запрещённая команда `rm`

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["rm","-f","test.txt"]}' | jq
```

Пример ответа:

```json
{
  "ok": false,
  "error": "command_denied",
  "message": "command is not allowed by policy",
  "request_id": "63a8078d-64a9-470d-9727-eff7344201e0",
  "server": "lifeorient",
  "argv": [
    "rm",
    "-f",
    "test.txt"
  ],
  "remote_command": null,
  "stdout": "",
  "stderr": "",
  "exit_code": null,
  "duration_ms": 0,
  "policy": null
}
```

### Запрещённый флаг `ls -R`

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["ls","-R","/"]}' | jq
```

### Запрещённый путь

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["ls","-la","/root/.ssh"]}' | jq
```

### Запрещённый glob

Если в политике:

```yaml
allowGlobs: false
```

то будет запрещено:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/exec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server":"lifeorient","argv":["ls","/*"]}' | jq
```

---

## 23. HTTP status vs exit_code

Важно различать:

### HTTP status

Это статус работы самого proxy/API.

| HTTP status | Значение |
|---|---|
| `200` | proxy успешно обработал запрос |
| `401` | нет токена или токен неверный |
| `403` | команда запрещена политикой |
| `404` | неизвестный server |
| `422` | невалидный JSON/request |
| `502` | ошибка SSH или remote execution |

### `exit_code`

Это код завершения удалённой команды.

Например команда может быть разрешена политикой, но завершиться с ошибкой:

```bash
ls /no-such-dir
```

Тогда HTTP может быть `200`, но:

```json
{
  "exit_code": 2,
  "stderr": "ls: cannot access '/no-such-dir': No such file or directory\n"
}
```

---

## CLI wrapper `pctl`

`pctl` — локальный CLI-wrapper, который отправляет команды в `pctl-proxy` через HTTP API.

Схема:

```text
pctl CLI
  -> HTTP REST API
    -> pctl-proxy
      -> policy check
        -> SSH
          -> remote server
```

### Установка

```bash
sudo install -m 755 wrapper/pctl.py /usr/local/bin/pctl
```

Проверка:

```bash
pctl --help
```

---

## Environment variables

```bash
export PCTL_PROXY_URL=http://127.0.0.1:8080
export PCTL_API_TOKEN=dev-local-token-change-me
```

Для server по умолчанию можно использовать:

```bash
export PCTL_DEFAULT_SSH_HOST=lifeorient
```

или старое имя:

```bash
export PCTL_DEFAULT_SERVER=lifeorient
```

Приоритет выбора server:

```text
1. --server
2. PCTL_SERVER
3. active server из ~/.config/pctl/state.json
4. PCTL_DEFAULT_SSH_HOST
5. PCTL_DEFAULT_SERVER
```

---

## Список серверов

```bash
pctl servers
```

Пример:

```text
* lifeorient    ssh_host=lifeorient    connected=True
  prod-master-1 ssh_host=prod-master-1 connected=False
```

`*` означает текущий active server.

---

## Active server

Показать текущий active server:

```bash
pctl active
```

Переключить active server:

```bash
pctl switch lifeorient
```

После этого можно не указывать `--server`:

```bash
pctl status
pctl exec -- df -h
```

---

## SSH connect/status/disconnect

```bash
pctl connect
pctl status
pctl disconnect
```

Или явно:

```bash
pctl --server lifeorient connect
pctl --server lifeorient status
pctl --server lifeorient disconnect
```

---

## Выполнение команды

```bash
pctl exec -- df -h
```

Или явно:

```bash
pctl --server lifeorient exec -- df -h
```

Wrapper печатает `stdout` удалённой команды в локальный `stdout`, `stderr` — в локальный `stderr`, и возвращает `exit_code` удалённой команды.

---

## JSON mode

```bash
pctl --json exec -- df -h
```

Вернёт полный JSON-ответ proxy.

---

## Запрещённая команда

```bash
pctl exec -- rm -f test.txt
```

Пример:

```text
pctl: command_denied: command is not allowed by policy
pctl: request_id=...
```

---

## Cancel / Ctrl-C

Wrapper генерирует `request_id` перед запуском команды.

Если во время выполнения нажать `Ctrl-C`, wrapper отправит:

```http
POST /api/v1/cancel
```

Пример:

```bash
pctl exec -- sleep 100
```

Нажать:

```text
Ctrl-C
```

Ожидаемый вывод:

```text
pctl: interrupted, sending cancel request_id=...
pctl: remote command cancelled: terminated
```

Также можно отменить команду вручную:

```bash
pctl cancel <request_id>
```

---

## Важно про cancel

Cancel работает для команд, запущенных через новую реализацию `asyncssh.create_process()`.

Команда отменяется через:

```text
terminate -> wait -> kill
```

Для сложных команд, которые порождают дочерние процессы на удалённой стороне, может потребоваться более строгая production-реализация с process group/session handling.

---

## 24. Текущие ограничения MVP

На текущем этапе:

- нет UI;
- нет audit log в файл;
- нет ротации логов;
- нет output filtering;
- нет masking секретов;
- политики пока достаточно простые;
- `kubectl` parsing пока минимальный;
- SSH config монтируется внутрь контейнера;
- один Bearer token на весь API;
- нет разграничения клиентов;
- нет HTTPS/mTLS;
- нет rate limiting;
- нет streaming output;
- stdout/stderr возвращаются целиком в JSON.

---

## 25. Что нужно продумать для production

### 25.1 Не использовать `root`

Сейчас тестовый сервер может подключаться под `root`.

Для production лучше:

```text
отдельный технический пользователь
минимальные права
без sudo или с очень ограниченным sudo
отдельный SSH key
```

---

### 25.2 Kubernetes лучше выполнять через Kubernetes API

Для Kubernetes-команд в будущем желательно рассмотреть:

```text
pctl-proxy -> Kubernetes API
```

а не:

```text
pctl-proxy -> SSH -> kubectl
```

Плюсы Kubernetes API:

- лучше RBAC;
- меньше shell-рисков;
- проще структурно фильтровать Secret/ConfigMap/Pod;
- проще аудит;
- проще ограничивать verbs/resources/namespaces.

---

### 25.3 RBAC и минимальные права

Даже если proxy фильтрует команды, на стороне Kubernetes должен быть ограниченный service account / kubeconfig.

Принцип:

```text
proxy не должен иметь больше прав, чем реально нужно
```

---

### 25.4 Политики нужно усложнить

Нужно будет отдельно продумать политики для:

- `kubectl get`;
- `kubectl logs`;
- `kubectl describe`;
- `kubectl exec`;
- `kubectl cp`;
- `kubectl port-forward`;
- `kubectl auth`;
- обычных Linux-команд.

Особенно опасен:

```bash
kubectl exec
```

Его лучше либо запретить, либо разрешить только по строгому allowlist внутренних команд.

---

### 25.5 Секреты и output filtering

Если разрешать:

```bash
kubectl get secret
kubectl describe secret
kubectl logs
cat config files
env
```

то в вывод могут попасть секреты.

Для production нужно:

- запретить чтение secrets по умолчанию;
- реализовать output filtering;
- реализовать masking/tokenization;
- не логировать реальные секреты;
- структурно парсить JSON/YAML, а не только regex.

---

### 25.6 Audit log

Нужен полноценный audit log:

- timestamp;
- request_id;
- caller/client identity;
- server;
- argv;
- decision allow/deny;
- matched policy;
- exit_code;
- duration;
- stdout/stderr size;
- SSH errors.

Полный stdout/stderr логировать опасно, потому что там могут быть секреты.

---

### 25.7 Token auth недостаточно для production

Bearer token подходит для MVP, но для production лучше рассмотреть:

- mTLS;
- OAuth2/JWT;
- per-client tokens;
- scopes;
- expiry;
- rotation;
- integration with Vault/Secrets Manager.

---

### 25.8 Не открывать API наружу без защиты

На MVP API слушает только:

```text
127.0.0.1:8080
```

Для production, если API будет доступен по сети, нужны:

- TLS;
- strong auth;
- network ACL/firewall;
- rate limiting;
- request limits;
- audit;
- monitoring.

---

### 25.9 Unix socket для локального режима

Если wrapper и proxy всегда на одной машине, можно использовать Unix socket вместо TCP:

```text
/var/run/pctl-proxy.sock
```

Плюсы:

- доступ контролируется правами файла;
- не открывается TCP-порт;
- проще локальная безопасность.

---

### 25.10 Ограничения stdout/stderr

Сейчас stdout/stderr возвращаются целиком.

Нужно добавить лимиты:

```yaml
limits:
  maxStdoutBytes: 10485760
  maxStderrBytes: 1048576
```

Или streaming output для долгих команд:

- WebSocket;
- Server-Sent Events;
- gRPC streaming;
- chunked HTTP.

---

### 25.11 Timeouts и cancellation

Нужно продумать:

- connect timeout;
- command timeout;
- idle timeout;
- отмену долгих команд;
- kill remote process;
- max concurrent commands.

---

### 25.12 SSH connection lifecycle

Нужно решить:

- сколько держать SSH-соединение;
- reconnect strategy;
- health checks;
- pool per server;
- max connections;
- что делать при перезапуске контейнера;
- как безопасно обновлять ключи.

---

### 25.13 Проверка путей и symlink bypass

Текущая проверка путей проверяет строку пути, а не реальный файл на сервере.

Например symlink внутри разрешённой директории может вести в запрещённую.

Для строгой production-безопасности нужно:

- не использовать root;
- ограничивать права пользователя на сервере;
- проверять `realpath` на удалённой стороне;
- или не разрешать произвольные filesystem paths вообще.

---

### 25.14 Docker secrets

Не хранить токены и ключи в plain environment/config для production.

Лучше:

- Docker secrets;
- Vault;
- Kubernetes Secrets;
- SOPS;
- sealed-secrets;
- systemd credentials.

---

### 25.15 Container hardening

Для production:

- pin versions;
- vulnerability scanning;
- non-root user;
- read-only filesystem;
- drop capabilities;
- resource limits;
- minimal image;
- SBOM.

---

## 26. Ближайшие следующие шаги

Рекомендуемый roadmap:

сделано 1. Добавить CLI-wrapper `pctl`, который вызывает HTTP API.
сделано 2. Добавить audit log в JSONL-файл.
3. Добавить лимиты stdout/stderr.
4. Добавить несколько серверов в YAML.
5. Улучшить kubectl policy parser.
kubectl -n default get pods
kubectl get pods -n default -o wide
kubectl get pod/my-pod -n default
kubectl get pods --all-namespaces
kubectl get pods -A
kubectl logs pod-name -n default
kubectl logs deployment/app -n default
kubectl describe pod pod-name -n default

Разбор global flags до subcommand
kubectl -n default get pods
kubectl --namespace default get pods

Разрешённые output formats
allowedOutput:
  - wide
  - name
  - yaml
  - json

И запретить опасные:
-o jsonpath=...
-o go-template=...
-o custom-columns=...

Запрет secrets
denyResources:
  - secrets
  - secret

Отдельная политика для logs
- name: allow-kubectl-logs
  command: kubectl
  subcommands: ["logs"]
  allowNamespaces: ["default", "stage"]
  allowedFlags:
    - "--tail"
    - "-n"
    - "--namespace"

Добавить kubectl shim
sudo mkdir -p /opt/pctl-shim
sudo ln -sf /usr/local/bin/pctl /opt/pctl-shim/kubectl
И для сервиса X:
PATH=/opt/pctl-shim:$PATH
PCTL_PROXY_URL=http://127.0.0.1:8080
PCTL_API_TOKEN=...
PCTL_DEFAULT_SSH_HOST=prod-master-1


6. Запретить опасные kubectl resources/verbs.
7. Добавить per-client auth/scopes.
8. Добавить output filtering для secrets.
9. Рассмотреть переход с SSH+kubectl на Kubernetes API для kube-операций.
10. Добавить token scopes
tokens:
  - name: local-dev
    token: dev-local-token-change-me
    servers:
      - lifeorient
    allowedPolicies:
      - allow-df-h
      - allow-ls-paths
11. Добавить audit event для policy deny
12. Добавить command hash
Чтобы не хранить чувствительные аргументы в будущем, можно писать:
"argv_sha256": "..."
13. Улучшить политики для Linux-команд
13.1. stringArgs
journalctl -u nginx --since "1 hour ago"
13.2. enumArgs
args:
  - type: enum
    values: ["status"]
  - type: enum
    values: ["nginx", "docker"]
13.3. regexArgs
14. Добавить install script
Чтобы не копировать вручную:
sudo install -m 755 wrapper/pctl.py /usr/local/bin/pctl
Можно сделать:
make install-wrapper



Ctrl-C/cancel отправляет cancel в SSH channel, но не гарантирует убийство процесса на удалённом сервере.
Для команд, которые остаются жить после cancel, требуется remote process group kill.