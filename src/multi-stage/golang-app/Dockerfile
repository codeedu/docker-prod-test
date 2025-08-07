FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY . .
RUN --mount=type=cache,target=/go/cache,id=go-mod \
    go mod tidy

RUN go build -o server .

FROM alpine:3.20 AS xpto

WORKDIR /app

RUN sleep 5
RUN echo "full cycle" > /app/fullcycle.txt

FROM scratch

COPY --from=builder /app/server /server
COPY --from=xpto /app/fullcycle.txt /fullcycle.txt
EXPOSE 8000

CMD ["/server"]