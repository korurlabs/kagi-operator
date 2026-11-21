# Build the manager binary
# The official golang image sets GOTOOLCHAIN=local, so this tag must be at least the `go`
# directive in go.mod or the build fails. Keep the two equal: 1.26.10 is the first release
# with the crypto/x509 and net/http fixes the operator's certificate and webhook code reaches.
FROM golang:1.26.10 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the Go source (relies on .dockerignore to filter)
COPY . .

# Build
# the GOARCH has no default value to allow the binary to be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
# No `-a`: it rebuilt the stdlib and every dep, so kagi-init reused nothing from
# manager -- 148.3s + 18.6s. CGO_ENABLED=0 alone gives the static binary.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o manager ./cmd

# Build the kagi-init launcher (secretless-delivery injector binary). It is
# bundled into the operator image so the mutating webhook's init container can
# stage it onto a workload pod's memory-backed emptyDir at runtime.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o kagi-init ./cmd/kagi-init

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/kagi-init /kagi-init
USER 65532:65532

ENTRYPOINT ["/manager"]
