# Imagen de NodeGoat endurecida (Módulo 2).
# Versión fija de la imagen base; usuario sin privilegios; sin secretos; solo el puerto de la app.
# NodeGoat es antigua: si la app no arranca, prueba otra versión de Node con --build-arg NODE_TAG=...
ARG NODE_TAG=16.20.2-alpine3.18
FROM node:${NODE_TAG}

ENV NODE_ENV=production
WORKDIR /app

# Primero solo los manifiestos: aprovecha la caché y deja las dependencias reproducibles (package-lock.json)
COPY --chown=node:node package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --chown=node:node . .

USER node
EXPOSE 4000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:4000/login || exit 1

CMD ["node", "server.js"]
