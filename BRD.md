# BRD: todoist-autoassign

**Зачем:** все задачи Todoist должны жить в проекте «Дела» (id `6j2Mq6hWq4h7vgv7`), без ручного переноса из Inbox/других проектов.

**Что:** FastAPI-сервис принимает вебхуки Todoist `item:added` / `item:updated` (подпись HMAC клиентским секретом); если задача не в «Дела» — переносит её (`POST /tasks/{id}/move`).

**Решения (журнал):**
- Подзадачи не трогаем: уезжают вместе с родителем.
- Переносим вообще все задачи (Todoist только личный).
- OAuth-токен (`data:read_write`), а не личный API-ключ: уже по правам, отзывается отдельно. Получаем один раз через `/oauth/start`, хранится в KV (`access_token`).
- Хостинг: Cloudflare Worker (TypeScript), не свой сервер: сервис крошечный, не нужны Docker/nginx, не рискуем остальными сайтами на `ssh my`. FastAPI-вариант отброшен. Токен OAuth — в Workers KV, секреты Todoist — `wrangler secret`.
- Без staging: push в `main` → tsc + vitest → `wrangler deploy` (GitHub Actions).
- Домен: `todoist-hook.vassilyv.me` — Custom Domain воркера.
- Цикла нет: после переноса задача уже в «Дела», повторный `item:updated` игнорируется.

**Не делаем:** очередь/ретраи, БД, UI, мультиюзер. Добавить, если вебхуки начнут теряться.
