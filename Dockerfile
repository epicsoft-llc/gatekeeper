FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG IMAGE_TAG="local"

RUN apk --no-cache upgrade && apk --no-cache add ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${IMAGE_TAG}" -o /out/gatekeeper ./cmd/gatekeeper

FROM scratch

ARG IMAGE_TAG="local"
ARG BUILD_DATE="development"
LABEL org.label-schema.name="gatekeeper" \
      org.label-schema.description="Sign-in gate for websites behind nginx auth_request or Traefik forwardAuth - one-time codes by email and OpenID Connect providers, access by group per host" \
      org.label-schema.vendor="epicsoft LLC / Alexander Schwarz <info@epicsoft.one>" \
      org.label-schema.url="https://gitlab.com/epicsoft-networks/gatekeeper" \
      org.label-schema.vcs-url="https://gitlab.com/epicsoft-networks/gatekeeper/tree/main" \
      org.label-schema.version=${IMAGE_TAG} \
      org.label-schema.schema-version="1.0" \
      org.label-schema.build-date=${BUILD_DATE}

LABEL image.name="epicsoft_gatekeeper" \
      image.description="Sign-in gate for websites behind nginx auth_request or Traefik forwardAuth" \
      maintainer="epicsoft LLC" \
      maintainer.name="Alexander Schwarz <info@epicsoft.one>" \
      maintainer.url="https://epicsoft.one/" \
      maintainer.copyright="Copyright 2026 epicsoft LLC / Alexander Schwarz"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/gatekeeper /gatekeeper

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/gatekeeper", "healthcheck"]
ENTRYPOINT ["/gatekeeper"]
