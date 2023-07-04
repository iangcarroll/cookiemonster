FROM golang:alpine as build
RUN go install github.com/iangcarroll/cookiemonster/cmd/cookiemonster@latest

FROM alpine
COPY --from=build /go/bin/cookiemonster /usr/bin/cookiemonster
ENTRYPOINT ["/usr/bin/cookiemonster"]
