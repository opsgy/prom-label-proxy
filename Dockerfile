FROM golang:1.15-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0

# Install ca-certificates
RUN apk update && apk add --no-cache ca-certificates && update-ca-certificates

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN GOOS=linux GOARCH=amd64 go build -o /out/prom-label-proxy . && ls /out

FROM scratch AS bin
USER 1001
ENTRYPOINT [ "/prom-label-proxy" ]
COPY --from=build /out/prom-label-proxy /prom-label-proxy



# ARG ARCH="amd64"
# ARG OS="linux"
# FROM quay.io/prometheus/busybox-${OS}-${ARCH}:glibc
# LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

# ARG ARCH="amd64"
# ARG OS="linux"
# COPY .build/${OS}-${ARCH}/prom-label-proxy /bin/prom-label-proxy

# USER        nobody
# ENTRYPOINT  [ "/bin/prom-label-proxy" ]
