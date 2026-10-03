# paddock-server image (plan M0 decision 18). Build context: repository root.
ARG GO_BUILD_IMAGE
ARG NODE_IMAGE
ARG RUNTIME_IMAGE

# Portal: built in the pinned Node image, embedded into the binary.
FROM ${NODE_IMAGE} AS web
WORKDIR /src/server/web
COPY server/web/package.json server/web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY server/web/ ./
RUN npm run build

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
COPY --from=web /src/server/web/dist/ server/web/dist/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /out/paddock-server ./server/cmd/paddock-server

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/paddock-server /paddock-server
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/paddock-server"]
