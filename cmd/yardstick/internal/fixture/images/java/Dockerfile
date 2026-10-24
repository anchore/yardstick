# one java package in two jars: log4j-core 2.14.1 from maven central, at two paths
FROM docker.io/library/node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
RUN wget -q -O /log4j-core-2.14.1.jar https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar \
 && echo "ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0  /log4j-core-2.14.1.jar" | sha256sum -c -

FROM scratch
COPY --from=build /log4j-core-2.14.1.jar /opt/app-a/lib/log4j-core-2.14.1.jar
COPY --from=build /log4j-core-2.14.1.jar /opt/app-b/lib/log4j-core-2.14.1.jar
