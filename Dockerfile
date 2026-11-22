# Hayel Ping Relay container. Works on any Docker host (Render, Railway, Fly.io, a VPS...).
# The host's $PORT is used automatically; default 25599.
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /src
COPY HayelPingRelay.java .
RUN javac HayelPingRelay.java

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /src/*.class ./
EXPOSE 25599
CMD ["java", "-XX:+UseSerialGC", "-Xmx96m", "HayelPingRelay"]
