require 'openssl'

module Fernet
  # Internal: Encapsulates encryption and signing primitives
  module Encryption
    AES_BLOCK_SIZE  = 16.freeze

    # Internal: Encrypts the provided message using a AES-128-CBC cipher with a
    #   random IV and the provided encryption key
    #
    # opts - a hash containing
    #   message: the message to encrypt
    #   key: the encryption key
    #   iv: override for the random IV, only used for testing
    #
    # Returns a two-element array containing the ciphertext and the random IV
    #
    # Examples
    #
    # ciphertext, iv = Fernet::Encryption.encrypt(
    #   message: 'this is a secret', key: encryption_key
    # )
    def self.encrypt(opts)
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv = opts[:iv] || cipher.random_iv
      cipher.iv  = iv
      cipher.key = opts[:key]
      [cipher.update(opts[:message]) + cipher.final, iv]
    end

    # Internal: Decrypts the provided ciphertext using a AES-128-CBC cipher with a
    #   the provided IV and encryption key
    #
    # opts - a hash containing
    #   ciphertext: encrypted message
    #   key: encryption key used to encrypt the message
    #   iv: initialization vector used in the ciphertext's cipher
    #
    # Returns a two-element array containing the ciphertext and the random IV
    #
    # Examples
    #
    # ciphertext, iv = Fernet::Encryption.encrypt(
    #   message: 'this is a secret', key: encryption_key
    # )
    def self.decrypt(opts)
      decipher = OpenSSL::Cipher.new('AES-128-CBC')
      decipher.decrypt
      decipher.iv  = opts[:iv]
      decipher.key = opts[:key]
      decipher.update(opts[:ciphertext]) + decipher.final
    end

    # Internal: Creates an HMAC signature (sha356 hashing) of the given bytes
    #   with the provided signing key
    #
    # key - the signing key
    # bytes - blob of bytes to sign
    #
    # Returns the HMAC signature as a string
    def self.hmac_digest(key, bytes)
      OpenSSL::HMAC.digest('sha256', key, bytes)
    end
  end
end
