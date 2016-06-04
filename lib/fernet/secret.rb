require 'base64'
require_relative 'errors'

module Fernet
  # Internal: Encapsulates a secret key, a 32-byte sequence consisting
  #   of an encryption and a signing key.
  class Secret
    class InvalidSecret < Fernet::Error; end

    # Internal - Initialize a Secret
    #
    # secret   - the secret, optionally encoded with either standard or
    #            URL safe variants of Base64 encoding
    # key_bits - number of bits in the AES key
    #
    # Raises Fernet::Secret::InvalidSecret if it cannot be decoded or is
    #   not of the expected length
    def initialize(secret, key_bits = 128)
      @key_bytes = key_bits / 8
      if secret.bytesize == @key_bytes * 2
        @secret = secret
      else
        begin
          @secret = Base64.urlsafe_decode64(secret)
        rescue ArgumentError
          @secret = Base64.decode64(secret)
        end
        unless @secret.bytesize == @key_bytes * 2
          raise InvalidSecret,
            "Secret must be #{@key_bytes * 2} bytes, instead got #{@secret.bytesize}"
        end
      end
    end

    # Internal: Returns the portion of the secret token used for encryption
    def encryption_key
      @secret.slice(@key_bytes, @key_bytes)
    end

    # Internal: Returns the portion of the secret token used for signing
    def signing_key
      @secret.slice(0, @key_bytes)
    end

    # Public: AES key size in bytes and bits
    def key_bytes
      @key_bytes
    end
    def key_bits
      @key_bytes * 8
    end

    # Public: String representation of this secret, masks to avoid leaks.
    def to_s
      "<Fernet::Secret key_bits=#{@key_bytes * 8} [masked]>"
    end
    alias to_s inspect
  end
end
