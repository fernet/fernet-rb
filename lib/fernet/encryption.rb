require 'openssl'

module Fernet
  module Encryption
    AES_BLOCK_SIZE  = 16.freeze

    def self.encrypt(opts)
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv = opts[:iv] || cipher.random_iv
      cipher.iv  = iv
      cipher.key = opts[:key]
      [cipher.update(opts[:message]) + cipher.final, iv]
    end

    def self.decrypt(opts)
      decipher = OpenSSL::Cipher.new('AES-128-CBC')
      decipher.decrypt
      decipher.iv  = opts[:iv]
      decipher.key = opts[:key]
      decipher.update(opts[:ciphertext]) + decipher.final
    end

    def self.hmac_digest(key, blob)
      OpenSSL::HMAC.digest('sha256', key, blob)
    end
  end
end
