# a rocky linux image's rpm database and os-release; several of its packages carry an epoch
FROM docker.io/rockylinux/rockylinux:9-minimal@sha256:e1d0a9f5ed99d52e7faf03afe7ee32e48b231c4dd9586808b3d1aedf894dff04 AS build

FROM scratch
COPY --from=build /etc/os-release /etc/os-release
COPY --from=build /var/lib/rpm /var/lib/rpm
