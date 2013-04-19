#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  class Generator

    attr_accessor :data

    def initialize(secret, data = '')
      @secret = Secret.new(secret)
      @data   = data
    end

    def generate
      yield self if block_given?
      iv, encrypted_data = encrypt
      issued_timestamp = Time.now.to_i
      payload = BitPacking.pack_int64_bigendian(issued_timestamp) +
        iv + encrypted_data
      mac = OpenSSL::HMAC.digest('sha256', secret.signing_key, payload)
      Base64.urlsafe_encode64(mac + payload)
    end

    def inspect
      "#<Fernet::Generator @secret=[masked] @data=#{@data.inspect}>"
    end
    alias to_s inspect

  private
    attr_reader :secret

    def encrypt
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv         = cipher.random_iv
      cipher.iv  = iv
      cipher.key = secret.encryption_key
      [iv, cipher.update(self.data) + cipher.final]
    end

  end
end
