FROM node:20-alpine

# Precisamos do git para dependências instaladas via repositórios
RUN apk add --no-cache git

WORKDIR /app

# Copia manifestos e instala dependências (sem dev)
COPY package*.json ./
RUN npm config set audit false \
 && npm config set fund false \
 && npm install --omit=dev

# Copia o restante do projeto
COPY . .

# Volume para persistir sessões
VOLUME ["/data"]

ENV PORT=3000
EXPOSE 3000

# Seu arquivo principal é servidor.js
CMD ["node", "servidor.js"]
