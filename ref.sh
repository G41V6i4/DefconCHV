docker compose down

./scripts/clean_up.sh

./build.sh
./scripts/build_all.sh


curl -X POST http://localhost:8080/start
