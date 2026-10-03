# paddock-server image (plan M0 decision 18). Build context: repository root.
ARG GO_BUILD_IMAGE
ARG RUNTIME_IMAGE

FROM ${GO_BUILD_IMAGE} AS build
WORKDIR /src
ENV GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.work go.work.sum ./
COPY pkg/go.mod pkg/
COPY server/go.mod server/go.sum server/
COPY test/acceptance/go.mod test/acceptance/go.sum test/acceptance/
RUN --mount=type=cache,target=/go/pkg/mod cd server && go mod download
COPY pkg/ pkg/
COPY server/ server/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /out/paddock-server ./server/cmd/paddock-server

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/paddock-server /paddock-server
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/paddock-server"]
