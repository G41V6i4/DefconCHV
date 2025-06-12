# can_bridge/Dockerfile
FROM gcc:latest

WORKDIR /app

COPY . /app/

RUN gcc -o bridge bridge.c -lpthread

CMD ["./bridge"]