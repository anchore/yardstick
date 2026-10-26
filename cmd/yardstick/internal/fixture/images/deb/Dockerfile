# a debian image's package database and os-release, and nothing else
FROM docker.io/library/debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS build

FROM scratch
COPY --from=build /etc/os-release /etc/os-release
COPY --from=build /var/lib/dpkg/status /var/lib/dpkg/status
