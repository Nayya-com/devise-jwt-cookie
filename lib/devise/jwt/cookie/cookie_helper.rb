module Devise
  module JWT
    module Cookie
      class CookieHelper
        include Cookie::Import['name', 'secure', 'same_site', 'domain']

        def build(token)
          if token.nil?
            remove_cookie
          else
            create_cookie(token)
          end
        end

        def read_from(cookies)
          cookies[name]
        end

        private

        def create_cookie(token)
          jwt = Warden::JWTAuth::TokenDecoder.new.call(token)
          res = {
            value: token,
            path: '/',
            httponly: true,
            secure: secure,
            same_site: same_site,
            expires: Time.at(jwt['exp'].to_i)
          }
          res[:domain] = domain if domain.present?
          [name, res]
        end

        def remove_cookie
          res = {
            value: nil,
            path: '/',
            httponly: true,
            secure: secure,
            same_site: same_site,
            max_age: '0',
            expires: Time.at(0)
          }
          res[:domain] = domain if domain.present?
          [name, res]
        end

      end
    end
  end
end