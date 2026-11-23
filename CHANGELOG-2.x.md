# Change Log for OXID eShop JWT Authentication Component

## v2.0.0 - Unreleased

### Added
- Support for PHP 8.5

### Changed
- Updated Symfony dependencies to ^7.3
- `ApiUser::eraseCredentials()` doesn't erase the password anymore, it's removed in `ApiUser::__serialize()`
- Updated PHPUnit to ^13.4

### Removed
- PHP 8.3 support
