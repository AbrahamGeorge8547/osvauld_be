# Build stage
FROM golang:1.22-alpine3.19 AS builder
WORKDIR /app
COPY . .
RUN go build -o main main.go

# Run stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates curl
WORKDIR /app

RUN curl -L https://github.com/golang-migrate/migrate/releases/download/v4.17.0/migrate.linux-amd64.tar.gz | tar xvz
RUN mv migrate /usr/local/bin/migrate

COPY --from=builder /app/main .
COPY --from=builder /app/templates ./templates

RUN mkdir db
COPY --from=builder /app/db/migration ./db/migration

COPY --from=builder /app/run_migration.sh ./run_migration.sh
RUN chmod +x ./run_migration.sh

EXPOSE 8000
ENTRYPOINT ["sh", "./run_migration.sh"]
CMD ["./main"]