require 'base64'

module Fernet
  # Internal: Encapsulates a secret key, a 32-byte sequence consisting
  #   of an encryption and a signing key.
  class Secret
    class InvalidSecret < RuntimeError; end

    # Internal - Initialize a Secret
    #
    # secret - the secret, encoded with either standard or URL safe variants
    #          of Base64 encoding
    #
    # Raises Fernet::Secret::InvalidSecret if it cannot be decoded or is
    #   not of the expected length
    def initialize(secret)
      begin
        @secret = Base64.urlsafe_decode64(secret)
      rescue ArgumentError
        @secret = Base64.decode64(secret)
      end
      unless @secret.bytesize == 32
        raise InvalidSecret, "Secret must be 32 bytes, instead got #{@secret.bytesize}"
      end
    end

    # Internal: Returns the portion of the secret token used for encryption
    def encryption_key
      @secret.slice(16, 16)
    end

    # Internal: Returns the portion of the secret token used for signing
    def signing_key
      @secret.slice(0, 16)
    end

    # Public: String representation of this secret, masks to avoid leaks.
    def to_s
      "<Fernet::Secret [masked]>"
    end
    alias to_s inspect
  end
end
