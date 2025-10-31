# Baileys Node Service (Option A)

Multi-tenant Baileys API to pair WhatsApp via QR and send messages.

## Endpoints
- `GET /healthz`
- `GET /sessions/:id/status`
- `GET /sessions/:id/qr`
- `POST /sessions/:id/messages` { to, text }
- `POST /sessions/:id/disconnect`

If `JWT_SECRET` is set, all endpoints (except `/healthz`) require `Authorization: Bearer <token>`.

## Run locally
```bash
cp .env.example .env
docker build -t baileys-service .
docker run -p 3000:3000 -v $(pwd)/data:/data --env-file .env baileys-service
```

## Deploy (Render/Railway)
- Create a new **Web Service** from this folder.
- Add a persistent volume mounted at `/data`.
- Add env vars from `.env.example`.
- Health check: `/healthz`
