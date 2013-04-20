#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  class Verifier
    class UnknownTokenVersion < RuntimeError; end

    attr_reader :token
    attr_accessor :ttl, :enforce_ttl

    def initialize(secret, opts = {})
      @secret      = Secret.new(secret)
      @ttl         = Configuration.ttl
      @enforce_ttl = Configuration.enforce_ttl
      @token       = opts[:token]
    end

    def verify
      yield self if block_given?

      deconstruct

      @must_verify = false
      @valid = signatures_match? && token_recent_enough?
    end

    def valid?
      verify if must_verify?
      @valid
    end

    def data
      verify if must_verify?
      @data
    end

    def ttl=(new_ttl)
      @must_verify = true
      @ttl = new_ttl
    end

    def enforce_ttl=(new_enforce_ttl)
      @must_verify = true
      @enforce_ttl = new_enforce_ttl
    end

    def inspect
      "#<Fernet::Verifier @secret=[masked] @token=#{@token} @data=#{@data.inspect} @ttl=#{@ttl} @enforce_ttl=#{@enforce_ttl}>"
    end
    alias to_s inspect

  private
    attr_reader :secret

    def must_verify?
      @must_verify || @valid.nil?
    end

    def deconstruct
      version = @token[0].to_s.unpack("C").first
      if version == Fernet::TOKEN_VERSION
        decoded_token       = Base64.urlsafe_decode64(@token[1..-1])
        @received_signature = decoded_token[(decoded_token.length - 32), 32]
        issued_timestamp    = BitPacking.unpack_int64_bigendian(decoded_token[0, 8])
        @issued_at          = DateTime.strptime(issued_timestamp.to_s, '%s')
        iv                  = decoded_token[8, 16]
        encrypted_data      = decoded_token[24..(decoded_token.length - 33)]
        @data = decrypt!(encrypted_data, iv)
        signing_blob = BitPacking.pack_int64_bigendian(issued_timestamp) +
          iv + encrypted_data
        @regenerated_mac = OpenSSL::HMAC.digest('sha256', secret.signing_key, signing_blob)
      else
        raise UnknownTokenVersion
      end
    end

    def token_recent_enough?
      if enforce_ttl?
        good_till = @issued_at + (ttl.to_f / 24 / 60 / 60)
        good_till > now
      else
        true
      end
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
      decipher.key = secret.encryption_key
      decipher.update(encrypted_data) + decipher.final
    end

    def enforce_ttl?
      @enforce_ttl
    end

    def now
      DateTime.now
    end
  end
end
