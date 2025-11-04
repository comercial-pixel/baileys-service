FROM node:20-alpine

WORKDIR /app
RUN apk add --no-cache git
COPY package*.json ./
RUN npm config set audit false \
 && npm config set fund false \
 && npm install --omit=dev
COPY . .

# healthcheck opcional (Render não usa por padrão, mas ajuda)
HEALTHCHECK CMD wget -qO- http://localhost:${PORT:-3000}/healthz || exit 1

ENV PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
