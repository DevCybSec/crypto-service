# 1. ETAPA DE CONSTRUCCIÓN (BUILDER)
FROM golang:1.25-alpine AS builder

WORKDIR /app
# Copiar archivos de dependencias
COPY go.mod go.sum ./
# Descargar dependencias
RUN go mod download

# Copiar el código fuente
COPY . .

# Construir el binario estático
RUN CGO_ENABLED=0 GOOS=linux go build -o /crypto-service .

# 2. ETAPA FINAL (PRODUCTION)
FROM alpine:latest
WORKDIR /root/
# Copiar el binario compilado
COPY --from=builder /crypto-service .
# Expone el puerto interno
EXPOSE 8081
# Comando de ejecución
CMD ["./crypto-service"]