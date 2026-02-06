# OXID eShop JWT Authentication Component

JWT-based authentication component for OXID eShop API endpoints.

## Features

- JWT token generation and validation
- Integration with OXID user system
- Role-based access control with Symfony Security
- `#[IsGranted]` and `#[CurrentUser]` attributes for protecting endpoints
- Ready-to-use login and profile endpoints

## Installation

```bash
composer require oxid-esales/jwt-authentication-component
```

## Configuration

Set the JWT secret key in your `.env` file:

```env
API_JWT_SECRET=your-secret-key-here
```

Generate a secure secret:

```bash
openssl rand -base64 64
```

## Usage

### Login

```bash
curl -X POST https://your-shop.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password"}'
```

To authenticate against a specific subshop, pass the `shp` query parameter:

```bash
curl -X POST "https://your-shop.com/api/login?shp=2" \
  -H "Content-Type: application/json" \
  -d '{"username": "user@example.com", "password": "password"}'
```

Response:

```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "username": "user@example.com",
    "roles": ["ROLE_USER"]
  }
}
```

### Protecting Endpoints

Use Symfony's `#[IsGranted]` attribute to protect endpoints:

```php
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

final readonly class MyApiController
{
    #[Route('/api/protected', methods: ['GET'])]
    #[IsGranted('IS_AUTHENTICATED')]
    public function getData(): Response
    {
        // Requires authentication
    }

    #[Route('/api/admin/settings', methods: ['GET'])]
    #[IsGranted('ROLE_ADMIN')]
    public function getSettings(): Response
    {
        // Requires ROLE_ADMIN
    }
}
```

### Accessing Authenticated User

```php
use OxidEsales\AuthComponent\Security\User\ApiUser;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

public function getData(#[CurrentUser] ApiUser $user): Response
{
    return new JsonResponse([
        'username' => $user->getUserIdentifier(),
        'roles' => $user->getRoles()
    ]);
}
```

## Available Roles

- `ROLE_USER` - All authenticated users
- `ROLE_ADMIN` - Admin users
- `ROLE_ADMIN_MALL` - Mall admin users

## Role Hierarchy

The component includes a configurable role hierarchy. By default, `ROLE_ADMIN_MALL` inherits `ROLE_ADMIN`, meaning mall admins can access all admin endpoints.

Default configuration in `services.yaml`:

```yaml
parameters:
  oxid_jwt_authenticator.role_hierarchy:
    ROLE_ADMIN_MALL:
      - ROLE_ADMIN
```

For more complex role hierarchies, implement `RoleResolverInterface` with custom resolution logic.

## License

Proprietary
