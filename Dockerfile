ARG CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX
FROM ${CI_DEPENDENCY_PROXY_GROUP_IMAGE_PREFIX}golang:1.17 as build

RUN apt install ca-certificates

RUN mkdir /aws-sigv4-proxy
WORKDIR /aws-sigv4-proxy
COPY go.mod .
COPY go.sum .

RUN go env -w GOPROXY=direct
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/aws-sigv4-proxy

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/aws-sigv4-proxy /go/bin/aws-sigv4-proxy

ENTRYPOINT [ "/go/bin/aws-sigv4-proxy" ]
