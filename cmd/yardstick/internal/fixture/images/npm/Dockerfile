# a scoped npm package at a version with a published advisory, installed by npm, keeping only the
# package.json files syft reads
FROM docker.io/library/node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /app
RUN npm init -y >/dev/null && npm install --no-audit --no-fund @babel/traverse@7.22.0 >/dev/null
RUN find node_modules -name package.json -not -path '*/test/*' | tar -cf /pkgs.tar -T -

FROM docker.io/library/node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS extract
COPY --from=build /pkgs.tar /pkgs.tar
RUN mkdir /out && tar -xf /pkgs.tar -C /out

FROM scratch
COPY --from=extract /out /app
