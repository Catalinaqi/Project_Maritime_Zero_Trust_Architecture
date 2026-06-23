# Immagine Node.js leggera per il servizio API.
FROM node:20-alpine

# Directory applicativa interna al container.
WORKDIR /app

# L'applicazione viene eseguita in modalità produzione.
ENV NODE_ENV=production

# Copia prima i manifest per sfruttare correttamente la cache Docker.
COPY package.json package-lock.json ./

# Installa esclusivamente le dipendenze di produzione.
# La verifica finale impedisce la creazione di un'immagine priva
# dei moduli indispensabili all'avvio dell'applicazione.
RUN npm ci --omit=dev --no-audit --no-fund && node -e "require.resolve('express'); require.resolve('mongodb'); console.log('[OK] express e mongodb installati correttamente')" && npm cache clean --force

# Copia il codice applicativo assegnandolo all'utente non privilegiato.
COPY --chown=node:node server.js ./

# Esecuzione senza privilegi amministrativi.
USER node

EXPOSE 3000

CMD ["node", "server.js"]