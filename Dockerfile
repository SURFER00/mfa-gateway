from alpine:3.22.1
WORKDIR ./
RUN mkdir -p /app/config
RUN apk add python3 py3-flask py3-requests py3-waitress
COPY --chmod=755 server.py /app/server.py
COPY --chmod=700 config.sample.json /app/config.json
ENTRYPOINT cd /app&&python /app/server.py