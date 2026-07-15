FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache nodejs-18 && rm -rf /var/cache/apk/*
USER nonroot
WORKDIR /home/nonroot
COPY --chown=nonroot:nonroot package.json ./
COPY --chown=nonroot:nonroot src/ src/
CMD ["sh", "-c", "node --test src/*.test.js"]
