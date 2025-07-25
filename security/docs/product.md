# Security Service – Project Summary

## High-Level Architecture
The service exposes REST endpoints for authentication/registration and protected business endpoints. It is completely stateless – sessions are not stored server-side; instead JWT tokens are issued and validated on each request.

```
┌────────────┐      /login (JSON)          ┌────────────────────┐
│  Client    │ ──────────────────────────▶ │JsonUsernamePassword│
│            │                            │AuthFilter          │
│            │      /register             │(credentials → AM)  │
│            │ ──────────────────────────▶ └────────────────────┘
│            │                            │ JwtAuthentication  │
│            │   Bearer <token>           │Filter (token → AM) │
│            │ ──────────────────────────▶ └────────────────────┘
└────────────┘                                     │
                                                  ▼
                                      Spring Security Filter Chain
                                                  │
                                                  ▼
                                           Auth Manager
                                                  │
                                     ┌────────────┴────────────┐
                                     │ DaoAuthenticationProvider│
                                     │ JwtAuthenticationProvider│
                                     └──────────────────────────┘
```

## Main Components
| Layer | Package / Class | Responsibility |
|-------|-----------------|----------------|
| **Entry-point** | `SecurityApp` | Spring Boot launcher |
| **API** | `api.controller.AuthController` | `/register` & `/csrf` endpoints |
| | `api.controller.SecuredController` | `/secured/**` sample endpoint |
| | `api.dto` | `LoginRequest`, `RegistrationRequest` DTOs |
| **Domain** | `domain.model.AuthUser` | JPA entity implementing `UserDetails` |
| | `domain.repository.UserRepository` | `findByEmail`, `save` |
| | `domain.service.UserService` | Persistence helper |
| | `domain.service.AuthService` | Handles registration & token issuance |
| | `domain.service.UserDetailsServiceImpl` | Required by Spring Security |
| **Security / Infrastructure** | `infrastructure.security.filter.*` | Custom servlet filters |
| | `JsonUsernamePasswordAuthFilter` | Reads JSON body `{email, password}` at `/login` and delegates to `AuthenticationManager` |
| | `JwtAuthenticationFilter` | Extracts `Authorization: Bearer` header and builds `JwtAuthenticationToken` |
| | `infrastructure.security.jwt.*` | Token wrapper, signing/verification logic (`JwtService`) |
| | `infrastructure.security.provider.JwtAuthenticationProvider` | Converts `JwtAuthenticationToken` to authenticated principle using `JwtService` |
| | `infrastructure.security.handler.*` | REST-style success / failure / entry-point / access-denied handlers |
| **Configuration** | `infrastructure.config.SecurityConfig` | Two `SecurityFilterChain`s: `public` (`/login`, `/register`, `/csrf`) and `secured` (`/secured/**`) |
| | `FilterConfig` | Wires filters and success/failure handlers |
| | `AuthenticationConfig` | Builds custom `AuthenticationManager` with DAO & JWT providers; defines `BCryptPasswordEncoder` |

## Authentication / Authorization Flow
1. **Login** – Client POSTs JSON `{email,password}` to `/login`.
   * `JsonUsernamePasswordAuthFilter` converts it to `UsernamePasswordAuthenticationToken` → DAO provider validates via database (BCrypt).
   * On success, `RestAuthenticationSuccessHandler` should generate and return JWT (implementation in handler layer, not shown above).
2. **Registration** – `POST /register` with JSON handled by `AuthController → AuthService.register` which:
   * Validates uniqueness, hashes password, stores `AuthUser`.
   * Generates JWT via `JwtService` and returns it (`JwtToken` wrapper).
3. **Access protected resources** – Add header `Authorization: Bearer <JWT>` when calling `/secured/**`.
   * `JwtAuthenticationFilter` pulls token, passes `JwtAuthenticationToken` to `AuthenticationManager`.
   * `JwtAuthenticationProvider` verifies signature & expiry via `JwtService`, builds authenticated `JwtAuthenticationToken` with user principal.
4. **CSRF** – `/csrf` endpoint provided for obtaining token when needed (public chain has CSRF enabled, secured chain disabled).

## Persistence
* Entity `AuthUser` maps to table `users` with columns `id`, `email`, `password`, `enabled`.
* JPA repository `UserRepository` not shown in snippet but provides `findByEmail`.
* Database connection configured via standard Spring properties (not committed in repo).

## Build & Run
```
./mvnw spring-boot:run
```
Requires env variables / `application.yaml` containing DB creds and `jwt.secret` (min 256-bit for HS256 algorithm).

## Notable Configuration Flags
* `jwt.secret` – HMAC secret for signing tokens. Injected into `JwtService`.
* `jwt.expiration-ms` – Defaults to 1 day (86 400 000 ms).
* Spring Profiles not defined; can add `dev`, `prod`, etc.
