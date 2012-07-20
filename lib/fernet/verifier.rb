require 'base64'
require 'json'
require 'openssl'
require 'date'

module Fernet
  class Verifier

    attr_reader :secret, :token, :data
    attr_writer :seconds_valid

    def initialize(secret)
      @secret        = secret
    end

    def verify_token(token)
      @token = token
      deconstruct

      custom_verification = yield self

      signatures_match? && token_recent_enough? && custom_verification
    end

    private

    def deconstruct
      @data               = JSON.parse(Base64.decode64(token))
      @received_signature = @data.delete('signature')
      @regenerated_mac    = OpenSSL::HMAC.hexdigest('sha256', JSON.dump(@data), secret)
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
  end
end
