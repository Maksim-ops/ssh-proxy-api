bash scripts/up.sh

Auth flow smoke-test:

1. Получить Bearer token по email:
curl -sS -X POST   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/auth/token   -d '{
    "email": "maksim.nikitin@flant.com"
  }'

2. Проверить текущего пользователя с этим token:
curl -sS   -H 'Authorization: Bearer <issued-token>'   http://127.0.0.1:8080/api/v1/auth/me

3. Выполнить date через pctl по старому static token:
PCTL_API_TOKEN=dev-local-token-change-me pctl --server lifeorient exec -- date

Или напрямую без launcher:
PCTL_API_TOKEN=dev-local-token-change-me python3 wrapper/pctl.py --server lifeorient exec -- date

Ручной smoke-тест через curl + pctl:

4. Проверка health:
curl -sS http://127.0.0.1:8080/health

5. Запустить long-running job через curl с выданным token:
curl -sS -X POST   -H 'Authorization: Bearer <issued-token>'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/exec   -d '{
    "request_id": "tail-f-1",
    "server": "lifeorient",
    "argv": ["tail", "-f", "/root/test.txt"],
    "client_type": "CLI"
  }'

6. Отменить job:
curl -sS -X POST   -H 'Authorization: Bearer <issued-token>'   -H 'Content-Type: application/json'   http://127.0.0.1:8080/api/v1/cancel   -d '{"request_id":"sleep-test-1"}'

7. Проверить jobs:
curl -sS   -H 'Authorization: Bearer <issued-token>'   http://127.0.0.1:8080/api/v1/jobs

8. Проверить audit:
curl -sS   -H 'Authorization: Bearer <issued-token>'   http://127.0.0.1:8080/api/v1/audit

9. Разлогиниться:
curl -sS -X POST   -H 'Authorization: Bearer <issued-token>'   http://127.0.0.1:8080/api/v1/auth/logout

10. Проверить файлы логов в volume:
find ./api-logs/jobs -maxdepth 3 -type f | sort

stdout/stderr команд лежат так:
./api-logs/jobs/<server>/<request_id>/stdout.log
./api-logs/jobs/<server>/<request_id>/stderr.log

Audit JSONL лежит так:
./api-logs/audit/audit.jsonl
