FROM node:23.0.0-slim AS ci


# comando para criar user no debian com pasta home
# RUN useradd -m node
# comando para criar user no alpine com pasta home
# RUN adduser -D node

USER node

RUN mkdir /home/node/app

WORKDIR /home/node/app

RUN --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/home/node/.npm,uid=1000,gid=1000,id=npm-cache \
    npm ci

COPY --chown=node:node . .

CMD [ "tail", "-f", "/dev/null" ]

FROM node:23.0.0-slim AS builder

ENV NODE_ENV=production

USER node

RUN mkdir /home/node/app

WORKDIR /home/node/app

COPY --from=ci --chown=node:node /home/node/app .
RUN npm run build

RUN --mount=type=cache,target=/home/node/.npm,uid=1000,gid=1000,id=npm-cache \
    npm ci --only=production

FROM node:23.0.0-slim AS production

ENV NODE_ENV=production

# RUN groupadd logswriters && \
#     usermod -aG logswriters node && \
#     chown root:logswriters /var/log && \
#     chmod 775 /var/log

RUN mkdir /var/log/myapp && chown node:node /var/log/myapp

USER node

RUN mkdir /home/node/app

WORKDIR /home/node/app

COPY --chown=node:node --from=builder /home/node/app/dist ./dist
COPY --chown=node:node --from=builder /home/node/app/node_modules ./node_modules
COPY --chown=node:node --from=builder /home/node/app/package.json ./


EXPOSE 3000

CMD [ "node", "dist/main.js" ]