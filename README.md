# matrix-key-server

Implementation of a key server for Matrix.

This is a fork of the original [t2bot/matrix-key-server](https://github.com/t2bot/matrix-key-server), adding a trusted-notary fallback for unreachable servers along with other changes.

**Caution**: Although this has notary server functionality, it is not yet recommended to point Synapse at this. It has not been tested - use at your own risk.

## Building and running

The key server will automatically generate itself a key to use on startup. The process is meant to be run 
only attached to a postgres instance and does not have any on-disk requirements other than the executable 
itself.

This project uses Go modules and requires Go 1.23 or higher.

```bash
# Build
git clone https://github.com/ricardo-duarte-av/matrix-key-server.git
cd matrix-key-server
go build -v -o bin/matrix-key-server

# Run
./bin/matrix-key-server -address="0.0.0.0" -port=8080 -domain="keys.example.com" -postgres="postgres://username:password@localhost/dbname?sslmode=disable" -notaries="matrix.org,tchncs.de,unredacted.org"
```

#### Trusted notaries

When an origin server is unreachable, the key server can fall back to a configured set of trusted
notaries to retrieve that server's keys. This allows it to serve keys for long-dead servers that were
cached by a notary while they were still alive (useful for verifying historical events).

Set the trusted notaries with the `-notaries` flag (or the `NOTARIES` environment variable) as a
comma-separated list of server names. It defaults to `matrix.org,tchncs.de,unredacted.org`. The first
notary whose response passes signature verification is used; only servers you actually trust should be
listed here, as the notary vouches for keys the origin can no longer confirm. To disable the fallback
entirely, pass an empty list (`-notaries=""`).

#### Docker

A pre-built multi-arch image is published to the GitHub Container Registry on
every push to `master`:

```bash
docker pull ghcr.io/ricardo-duarte-av/matrix-key-server:latest
```

Alternatively, build your own from this repository:

```bash
docker build -t matrix-key-server .
```

Then run it (all flags are also configurable as environment variables):

```bash
docker run -it --rm -e "ADDRESS=0.0.0.0" -e "PORT=8080" -e "DOMAIN=keys.example.com" -e "POSTGRES=postgres://username:password@localhost/dbname?sslmode=disable" -e "NOTARIES=matrix.org,tchncs.de,unredacted.org" ghcr.io/ricardo-duarte-av/matrix-key-server:latest
```

#### Docker Compose

A [`docker-compose.yaml`](docker-compose.yaml) is included that runs the key
server together with its own PostgreSQL database:

```bash
# Edit docker-compose.yaml first: set DOMAIN to your key server's domain and
# change the PostgreSQL credentials.
docker compose up -d
```

The compose file exposes the key server on host port `8080`. Terminate TLS with a
reverse proxy in front of it for production use. Database contents are persisted
in the `postgres-data` volume; the key server generates and stores its signing
key in PostgreSQL on first start, so keep that volume to preserve your server's
identity.

## Custom APIs

The key server exposes some custom APIs which may aide the development of homeservers or Matrix services.

#### `POST /_matrix/key/unstable/check_auth`

Verifies an auth header according to the Matrix specification. The `Authorization` header is passed through
and the remaining headers shown here demonstrate the additional information the key server needs. The content
for the API call is sent as the request body to this call.

**Caution**: Trusting this endpoint can be bad if you don't trust the key server. You should always do your own
auth wherever possible.

**Example request**:
```
POST /_matrix/key/unstable/check_auth
Authorization: X-Matrix origin="example.org",key="ed25519:auto",sig="ABCDEF..."
X-Keys-Method: GET
X-Keys-URI: /_matrix/federation/v1/publicRooms?include_all_networks=false&limit=20
X-Keys-Destination: dest.example.org

{... request body ...}
```

If the response is a `200 OK`, the server is authorized. All other responses should be considered unauthorized.
