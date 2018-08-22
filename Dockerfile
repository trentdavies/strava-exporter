# gobase layer
FROM golang:1.10 AS go-base
WORKDIR /go/src/strava-exporter
ADD strava-exporter.go .
RUN go get -d -v
RUN CGO_ENABLED=0 GOOS=linux go build -o strava-exporter

# final layer
FROM alpine
COPY --from=go-base /go/src/strava-exporter/strava-exporter /app/
EXPOSE 8080
ENTRYPOINT ["/app/strava-exporter"]
