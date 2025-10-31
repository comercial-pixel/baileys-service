FROM node:20-alpine
WORKDIR /app

# Copia arquivos de dependência e instala
COPY package*.json ./
RUN npm install --omit=dev

# Copia todo o restante do projeto
COPY . .

# Volume para persistir sessões do WhatsApp
VOLUME ["/data"]

ENV PORT=3000
EXPOSE 3000

# Corrigido para seu arquivo real: servidor.js
CMD ["node", "servidor.js"]
