FROM node:23.0.0-slim

ENV NODE_ENV=production

WORKDIR /home/node/app

# root
RUN --mount=type=bind,source=./package.json,target=package.json \
    --mount=type=bind,source=./package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev