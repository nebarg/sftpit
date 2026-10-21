# The Linux environment for make linux-check: Go, OpenSSH's sftp client and
# server, and PHP for phpseclib, so that every test runs, the conformance
# tests among them.
FROM golang:1.26-trixie
RUN apt-get update \
 && apt-get install --yes --no-install-recommends openssh-client openssh-sftp-server php-cli php-gmp php-mbstring \
 && rm -rf /var/lib/apt/lists/*
# The tests run as a user who is not root, as they do on a developer's
# machine, because root can change any file's owner and read or write any file.
RUN useradd --create-home tester
USER tester
RUN mkdir -p /home/tester/.cache /home/tester/go
ENV HOME=/home/tester GOPATH=/home/tester/go GOCACHE=/home/tester/.cache/go-build GOTOOLCHAIN=local
WORKDIR /src
