# The sftpit image: a static binary on a distroless base, which has no shell,
# runs as a user who is not root and has a writable /tmp for the temporary
# workspace.
FROM golang:1.26-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
# The repository's .git comes too, so the build records the same version as
# make build does.
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/sftpit ./cmd/sftpit

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/sftpit /usr/local/bin/sftpit
EXPOSE 2122 8122
ENTRYPOINT ["/usr/local/bin/sftpit"]
CMD ["serve", "--profile", "container"]
