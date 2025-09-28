FROM node:24.8.0-slim AS ci

# baseado no quanto as instruções podem mudar
# instruções que não mudam ou pouco mudam devem ficar no topo
# ENV, ARG, RUN apt update, apt install

RUN apt update && apt install -y \
    git \
    curl && \
    rm -rf /var/lib/apt/lists/*

# deterministicas e não deterministicas

#RUN echo "hello world" > test.txt

# ARG BUILD_TIMESTAMP
# RUN echo "$BUILD_TIMESTAMP" > /build_time.txt

# add vs copy

#ADD --checksum=sha256:278888 http://ftp.de.debian.org/debian/pool/main/c/curl/curl_7.88.1-10+deb12u12_amd64.deb /tmp/curl.deb
# RUN script.sh
# gzip, bzip2 or xz
ADD curl-8.15.0.tar.gz /tmp/test


USER node

RUN mkdir /home/node/app

WORKDIR /home/node/app

RUN --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/home/node/.npm,uid=1000,gid=1000,id=npm-cache \
    npm ci

COPY --chown=node:node . .

CMD [ "tail", "-f", "/dev/null" ]

FROM node:24.8.0-slim AS builder

ENV NODE_ENV=production

USER node

RUN mkdir /home/node/app

WORKDIR /home/node/app

COPY --from=ci --chown=node:node /home/node/app .
RUN npm run build

RUN --mount=type=cache,target=/home/node/.npm,uid=1000,gid=1000,id=npm-cache \
    npm ci --only=production

FROM node:24.8.0-slim AS production

ENV NODE_ENV=production

USER node

RUN mkdir /home/node/app

WORKDIR /home/node/app

COPY --chown=node:node --from=builder /home/node/app/dist ./dist
COPY --chown=node:node --from=builder /home/node/app/node_modules ./node_modules
COPY --chown=node:node --from=builder /home/node/app/package.json ./

EXPOSE 3000

CMD [ "node", "dist/main.js" ]