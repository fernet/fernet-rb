require 'base64'
module Fernet
  class Secret
    class InvalidSecret < RuntimeError; end

    def initialize(secret)
      @secret = Base64.urlsafe_decode64(secret)
      unless @secret.bytesize == 32
        raise InvalidSecret, "Secret must be 32 bytes, instead got #{@secret.bytesize}"
      end
    end

    def encryption_key
      @secret.slice(16, 16)
    end

    def signing_key
      @secret.slice(0, 16)
    end
  end
end
