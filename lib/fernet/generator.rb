#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  class Generator
    attr_accessor :data

    def initialize(secret)
      @secret  = Secret.new(secret)
      @data    = ''
    end

    def generate
      yield self if block_given?
      iv, encrypted_data = encrypt(data)
      issued_timestamp = Time.now.to_i
      payload = [issued_timestamp].pack("Q>") + iv + encrypted_data
      mac = OpenSSL::HMAC.hexdigest('sha256', secret.signing_key, payload)
      Base64.urlsafe_encode64(mac + payload)
    end

    def inspect
      "#<Fernet::Generator @secret=[masked] @data=#{@data.inspect}>"
    end
    alias to_s inspect

  private
    attr_reader :secret

    def encrypt(data)
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv         = cipher.random_iv
      cipher.iv  = iv
      cipher.key = secret.encryption_key
      [iv, cipher.update(data) + cipher.final]
    end
  end
end
