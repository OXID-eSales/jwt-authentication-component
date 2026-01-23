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

Response:

```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": "abc123",
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

#### Using #[CurrentUser] Attribute (Recommended)

```php
use OxidEsales\AuthComponent\Security\User\ApiUser;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

public function getData(#[CurrentUser] ApiUser $user): Response
{
    return new JsonResponse([
        'user_id' => $user->getUserId(),
        'username' => $user->getUserIdentifier(),
        'roles' => $user->getRoles()
    ]);
}
```

#### Using Request Attributes

```php
public function getData(Request $request): Response
{
    $user = $request->attributes->get('_api_user');

    return new JsonResponse([
        'user_id' => $user->getUserId(),
        'username' => $user->getUserIdentifier()
    ]);
}
```

## Available Roles

- `ROLE_USER` - All authenticated users
- `ROLE_ADMIN` - Admin users
- `ROLE_ADMIN_MALL` - Mall admin users

## Role Hierarchy

The component includes a configurable role hierarchy. By default, `ROLE_ADMIN_MALL` inherits `ROLE_ADMIN`, meaning mall admins can access all admin endpoints.

Configure in `services.yaml`:

```yaml
parameters:
  oxid_jwt_authenticator.role_hierarchy:
    ROLE_ADMIN_MALL:
      - ROLE_ADMIN
    ROLE_SUPER_ADMIN:
      - ROLE_ADMIN_MALL
      - ROLE_MODERATOR
```

## License

Proprietary
