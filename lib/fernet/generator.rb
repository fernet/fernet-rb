require 'base64'
require 'multi_json'
require 'openssl'
require 'date'

module Fernet
  class Generator
    attr_accessor :data, :payload

    def initialize(secret, encrypt)
      @secret  = Secret.new(secret, encrypt)
      @encrypt = encrypt
      @payload = ''
      @data    = {}
    end

    def generate
      yield self if block_given?
      data.merge!(:issued_at => DateTime.now)

      if encrypt?
        iv = encrypt_data!
        @payload = "#{base64(data)}|#{base64(iv)}"
      else
        @payload = base64(MultiJson.dump(data))
      end

      mac = OpenSSL::HMAC.hexdigest('sha256', payload, signing_key)
      "#{payload}|#{mac}"
    end

    def inspect
      "#<Fernet::Generator @secret=[masked] @data=#{@data.inspect}>"
    end
    alias to_s inspect

    def data
      @data ||= {}
    end

  private
    attr_reader :secret

    def encrypt_data!
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      iv         = cipher.random_iv
      cipher.iv  = iv
      cipher.key = encryption_key
      @data = cipher.update(MultiJson.dump(data)) + cipher.final
      iv
    end

    def base64(chars)
      Base64.urlsafe_encode64(chars)
    end

    def encryption_key
      @secret.encryption_key
    end

    def signing_key
      @secret.signing_key
    end

    def encrypt?
      @encrypt
    end

  end
end
