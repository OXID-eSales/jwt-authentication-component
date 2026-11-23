# Change Log for OXID eShop JWT Authentication Component

## v1.2.0 - Unreleased

### Added
- Support for PHP 8.5

### Changed
- Updated PHPUnit to ^13.4

### Removed
- PHP 8.3 support

## v1.1.0 - 2026-10-15

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