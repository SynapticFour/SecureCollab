# SPDX-License-Identifier: Apache-2.0
FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build \
    && addgroup -S app && adduser -S app -G app \
    && chown -R app:app /app

USER app
EXPOSE 3000
CMD ["npm", "run", "start", "--", "-H", "0.0.0.0", "-p", "3000"]
