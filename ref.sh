docker compose down

./scripts/clean_up.sh

./scripts/build_all.sh

./build.sh

curl -X POST http://localhost:8080/start