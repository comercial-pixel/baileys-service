FROM node:20-alpine
RUN apk add --no-cache git
WORKDIR /app

COPY package*.json ./
RUN npm config set audit false \
 && npm config set fund false \
 && npm install --omit=dev

COPY . .

# 👇 Debug: mostrar se servidor.js está na imagem
RUN echo "=== CONTEÚDO DE /app ===" && ls -la /app

VOLUME ["/data"]
ENV PORT=3000
EXPOSE 3000

CMD ["node", "servidor.js"]

