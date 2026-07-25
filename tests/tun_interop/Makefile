.PHONY: docker-build docker-run clean

docker-build:
	docker build -t tinytcp-tun-test -f Dockerfile ../..

docker-run: docker-build
	docker run --rm --cap-add=NET_ADMIN --device=/dev/net/tun tinytcp-tun-test

# Run via docker-compose
compose:
	docker compose up --build --abort-on-container-exit

clean:
	docker rmi tinytcp-tun-test 2>/dev/null || true
