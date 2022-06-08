module Devise
  module JWT
    module Cookie
      class Middleware
        include Cookie::Import['expiration_header_name']

        attr_reader :app, :config

        def initialize(app)
          @app = app
          @config = Warden::JWTAuth.config
        end

        def call(env)
          token_should_be_revoked = token_should_be_revoked?(env)
          if token_should_be_revoked
            # add the Authorization header, devise-jwt needs this to revoke tokens
            # we need to make sure this is done before the other middleware is run
            request = ActionDispatch::Request.new(env)
            env['HTTP_AUTHORIZATION'] = "Bearer #{CookieHelper.new.read_from(request.cookies)}"
          end

          status, headers, response = app.call(env)

          new_token = env[Warden::JWTAuth::Hooks::PREPARED_TOKEN_ENV_KEY]

          if headers['Authorization'] && new_token
            # If devise-jwt is providing a token via Authorization header, add a cookie w/ the token:
            name, cookie = CookieHelper.new.build(new_token)
            Rack::Utils.set_cookie_header!(headers, name, cookie)

            # And, set a header so the client can track the expiration of the token
            headers[expiration_header_name] = expiration(new_token)
          elsif token_should_be_revoked
            # Else, if token is being revoked, add a set-cookie header to remove the cookie:
            name, cookie = CookieHelper.new.build(nil)
            Rack::Utils.set_cookie_header!(headers, name, cookie)
          end

          [status, headers, response]
        end

        def token_should_be_revoked?(env)
          path_info = env['PATH_INFO'] || ''
          method = env['REQUEST_METHOD']
          revocation_requests = config.revocation_requests
          revocation_requests.each do |tuple|
            revocation_method, revocation_path = tuple
            return true if path_info.match(revocation_path) &&
                           method == revocation_method
          end
          false
        end

        def expiration(token)
          Warden::JWTAuth::TokenDecoder.new.call(token)['exp']
        end
      end
    end
  end
end