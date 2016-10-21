# Lumen with JWT Authentication

Basically this is a starter kit for you to integrate Lumen with [JWT Authentication](https://jwt.io/).

## What's Added

- Lumen 5.3
- [JWT Auth](https://github.com/tymondesigns/jwt-auth) for Lumen Application

## Quick Start

- Clone this repo
- Run `composer install`
- Configure your `.env` file for a database usage
- Run `php artisan migrate --seed`

## A Live PoC

- Run a PHP built in server from your root project:

```sh
php -S localhost:8000 -t public/
```

To authenticate a user, make a `POST` request to `/auth/login` with parameter as mentioned below:

```
email: johndoe@example.com
password: johndoe
```

- With token provided by above request, you can check authenticated user by sending a `GET` request to: `/auth/user`.
- To refresh your token, simply send a `PATCH` request to `/auth/refresh`.
- Last but not least, you can also invalidate token by sending a `DELETE` request to `/auth/invalidate`.

> **NOTES** I add [Lumen Generator](https://github.com/flipboxstudio/lumen-generator) to make development even easier and faster.
