# JWT Auth Service

This project is a minimal demonstration of issuing JSON Web Tokens (JWTs) using Spring Boot. Each API client is stored in PostgreSQL and has its own RSA key pair for signing tokens. Secrets are encrypted using AES before being persisted.

## How it works

1. **API clients** – `ApiClient` entities are stored in the database. When a new client first requests a token, a RSA key pair is generated and the private key is encrypted before being saved. The `ApiClientService` handles CRUD operations.
2. **Token issuance** – `/token` accepts a `clientId` and `clientSecret`. When the secret matches the stored client, the `TokenService` generates an access token (valid for one hour) and a refresh token (valid for seven days) using `JwtUtil`.
3. **Token refresh** – `/token/refresh` takes a refresh token. If it is valid, a new token pair is produced.
4. **Token validation** – `TokenFilter` intercepts requests to paths beginning with `/secure`. It validates the JWT and, if valid, places the authenticated user in the `SecurityContextHolder` so the controller can access it.

## Running locally

The service requires a running PostgreSQL instance. Update `src/main/resources/application.yaml` with the correct credentials and run:

```bash
sh ./mvnw spring-boot:run
```

Tests can be executed with:

```bash
sh ./mvnw test
```

Note: tests start the Spring context and will attempt to connect to the configured database.

## API endpoints

| Method | Path            | Description                                     |
|------- |----------------|-------------------------------------------------|
| POST   | `/token`       | Issue a new access and refresh token             |
| POST   | `/token/refresh` | Refresh an existing access token                |
| GET    | `/secure/test` | Example secured endpoint (requires `Authorization: Bearer <token>`) |
| GET    | `/test`        | Public endpoint for basic connectivity checks    |

## Building

The project uses the Maven wrapper. All dependencies are declared in `pom.xml`. The build target produces a Spring Boot fat JAR located in `target/`.

```bash
sh ./mvnw package
```

This will run the tests and create `target/jwt-auth-0.0.1-SNAPSHOT.jar`.
