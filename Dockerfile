FROM golang:1.26-alpine AS build
# TAGS=awskms adds AWS KMS support and the AWS SDK; the default image has neither.
ARG TAGS=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -tags "$TAGS" -o /sealbox ./cmd/sealbox

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /sealbox /sealbox
EXPOSE 8080
ENTRYPOINT ["/sealbox"]
