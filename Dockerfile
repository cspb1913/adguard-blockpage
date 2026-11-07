FROM python:3.13-alpine
RUN adduser -D -H blockpage
WORKDIR /app
COPY server.py ./
COPY public ./public
USER blockpage
ENV BLOCKPAGE_LISTEN=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK CMD wget -q -O /dev/null --header 'Host: healthcheck.invalid' http://127.0.0.1:8080/__blockpage/cspb-logo.png || exit 1
CMD ["python3", "-u", "server.py"]
