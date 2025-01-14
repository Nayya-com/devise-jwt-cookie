# Devise::JWT::Cookie

`devise-jwt-cookie` is a [devise](https://github.com/plataformatec/devise) extension based on [devise-jwt](https://github.com/waiting-for-dev/devise-jwt). It should be used alongside `devise-jwt`.

# Changes made by this fork
- Upgraded dependencies
- Added `same_site` option for the cookie (default to "Lax")
- Added header to return JWT expiration to client, with customizable name via `expiration_header_name` option
  - NOTE: this header is included with every response, not just the ones that set 
- Removed `Authorization` header that `devise-jwt` sets to further secure against JS XSS attacks
- Added support for `aud` header
- Only overwrite Authorization header w/ cookie value if it's not already set

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'devise-jwt-cookie', git: 'https://github.com/Nayya-com/devise-jwt-cookie.git', branch: 'main'
```

And then execute:

```bash
bundle
```

## Usage

First you need to setup up and configure devise and devise-jwt. This gem hooks into devise-jwt to add an httpOnly cookie with the JWT.

### Model configuration

You have to update the user model to be able to use the cookie method. For example:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable,
         :jwt_cookie_authenticatable,
         :jwt_authenticatable, jwt_revocation_strategy: Blacklist
end
```

### Configuration reference

This library can be configured by calling `jwt_cookie` on the devise config object:

```ruby
Devise.setup do |config|
  config.jwt do |jwt|
    # config for devise-jwt goes here
  end
  config.jwt_cookie do |jwt_cookie|
    # ...
    jwt_cookie.secure = false if Rails.env.development?
  end
end
```

#### name

The name of the cookie. Defaults to `access_token`.

#### domain

The domain the cookie should be issued to. Will be omitted if not set.

#### secure

If a secure cookie should be set, this means the cookie must be sent over a secure connection. Defaults to true.

