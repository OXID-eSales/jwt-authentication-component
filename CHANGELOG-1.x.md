# Change Log for OXID eShop JWT Authentication Component

## v1.1.0 - Unreleased

### Added
- `OxidAwareUserInterface` for type safe access to OXID user

## v1.0.0 - 2026-04-08

### Added
- JWT token-based authentication for API endpoints
- Login (`POST /api/login`) endpoint
- Role-based access control via `#[IsGranted]` attribute
- `#[CurrentUser]` attribute for injecting the authenticated user
- Configurable role hierarchy via `oxid_jwt_authenticator.role_hierarchy` parameter
- `RoleResolverInterface` for custom role resolution
- `TokenServiceInterface` for custom token handling
- OXID password hasher integration with Symfony Security
- Configurable token expiration