require 'dry/configurable'
require 'dry/auto_inject'
require 'devise/jwt/cookie/strategy'

# Authentication library
module Devise
  def self.jwt_cookie
    yield(Devise::JWT::Cookie.config)
  end

  add_module(:jwt_cookie_authenticatable, strategy: :jwt_cookie)

  module JWT
    module Cookie
      extend Dry::Configurable

      setting :name, default: 'access_token'
      setting :expiration_header_name, default: 'JWT-Expiration'
      setting :secure, default: true
      setting :same_site, default: 'Lax' # Default to "SameSite=Lax", which provides partial CSRF defense without interrupting user experience
      setting :domain

      Import = Dry::AutoInject(config)
    end
  end
end

require 'devise/jwt/cookie/version'
require 'devise/jwt/cookie/railtie'
require 'devise/jwt/cookie/cookie_helper'
require 'devise/jwt/cookie/middleware'
require 'devise/jwt/cookie/models'