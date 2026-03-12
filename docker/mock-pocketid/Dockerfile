FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN go build -o /mock-pocketid .

FROM alpine:3.19
COPY --from=builder /mock-pocketid /mock-pocketid
EXPOSE 8081
CMD ["/mock-pocketid"]
