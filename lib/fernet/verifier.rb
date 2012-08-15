require 'base64'
require 'yajl'
require 'openssl'
require 'date'

module Fernet
  class Verifier
    attr_reader :token, :data
    attr_writer :seconds_valid

    def initialize(secret, decrypt)
      @secret  = Secret.new(secret, decrypt)
      @decrypt = decrypt
    end

    def verify_token(token)
      @token = token
      deconstruct

      if block_given?
        custom_verification = yield self
      else
        custom_verification = true
      end

      signatures_match? && token_recent_enough? && custom_verification
    end

    def inspect
      "#<Fernet::Verifier @secret=[masked] @token=#{@token} @data=#{@data.inspect} @seconds_valid=#{@seconds_valid}>"
    end
    alias to_s inspect

  private
    attr_reader :secret

    def deconstruct
      parts = @token.split('|')
      if decrypt?
        encrypted_data, iv, @received_signature = *parts
        @data = Yajl::Parser.parse(decrypt!(encrypted_data, Base64.urlsafe_decode64(iv)))
        signing_blob = "#{encrypted_data}|#{iv}"
      else
        encoded_data, @received_signature = *parts
        signing_blob = encoded_data
        @data = Yajl::Parser.parse(Base64.urlsafe_decode64(encoded_data))
      end
      @regenerated_mac = OpenSSL::HMAC.hexdigest('sha256', signing_blob, signing_key)
    end

    def token_recent_enough?
      DateTime.parse(data['issued_at']) > (DateTime.now - 60)
    end

    def signatures_match?
      regenerated_bytes = @regenerated_mac.bytes.to_a
      received_bytes    = @received_signature.bytes.to_a
      received_bytes.inject(0) do |accum, byte|
        accum |= byte ^ regenerated_bytes.shift
      end.zero?
    end

    def decrypt!(encrypted_data, iv)
      decipher = OpenSSL::Cipher.new('AES-128-CBC')
      decipher.decrypt
      decipher.iv  = iv
      decipher.key = encryption_key
      decipher.update(Base64.urlsafe_decode64(encrypted_data)) + decipher.final
    end

    def encryption_key
      @secret.encryption_key
    end

    def signing_key
      @secret.signing_key
    end

    def decrypt?
      @decrypt
    end

  end
end
