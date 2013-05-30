#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  class Verifier
    class UnknownTokenVersion < RuntimeError; end

    MAX_CLOCK_SKEW = 60.freeze

    attr_reader :token
    attr_accessor :ttl, :enforce_ttl

    def initialize(opts = {})
      @secret      = Secret.new(opts.fetch(:secret))
      @ttl         = opts[:ttl] || Configuration.ttl
      @enforce_ttl = Configuration.enforce_ttl
      @token       = opts[:token]
      @now         = opts[:now]
    end

    def verify
      yield self if block_given?

      deconstruct

      @must_verify = false
      @valid = signatures_match? && token_recent_enough?
    end

    def valid?
      begin
        verify if must_verify?
        @valid
      rescue
        false
      end
    end

    def message
      verify if must_verify?
      @message
    end

    def data
      puts "[WARNING] data is deprected. Use message instead"
      message
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
      "#<Fernet::Verifier @secret=[masked] @token=#{@token} @message=#{@message.inspect} @ttl=#{@ttl} @enforce_ttl=#{@enforce_ttl}>"
    end
    alias to_s inspect

  private
    attr_reader :secret

    def must_verify?
      @must_verify || @valid.nil?
    end

    def deconstruct
      decoded_token = Base64.urlsafe_decode64(@token)
      version = decoded_token.chr.unpack("C").first
      if version == Fernet::TOKEN_VERSION
        @received_signature = decoded_token[(decoded_token.length - 32), 32]
        issued_timestamp    = BitPacking.unpack_int64_bigendian(decoded_token[1, 8])
        @issued_at          = Time.at(issued_timestamp).to_date
        iv                  = decoded_token[9, 16]
        encrypted_message      = decoded_token[25..(decoded_token.length - 33)]
        @message = decrypt!(encrypted_message, iv)
        signing_blob = [Fernet::TOKEN_VERSION].pack("C") + BitPacking.pack_int64_bigendian(issued_timestamp) +
          iv + encrypted_message
        @regenerated_mac = OpenSSL::HMAC.digest('sha256', secret.signing_key, signing_blob)
      else
        raise UnknownTokenVersion
      end
    end

    def token_recent_enough?
      if enforce_ttl?
        good_till = @issued_at + (ttl.to_f / 24 / 60 / 60)
        (good_till > now) && acceptable_clock_skew?
      else
        true
      end
    end

    def acceptable_clock_skew?
      @issued_at < (now + MAX_CLOCK_SKEW)
    end

    def signatures_match?
      regenerated_bytes = @regenerated_mac.bytes.to_a
      received_bytes    = @received_signature.bytes.to_a
      received_bytes.inject(0) do |accum, byte|
        accum |= byte ^ regenerated_bytes.shift
      end.zero?
    end

    def decrypt!(encrypted_message, iv)
      decipher = OpenSSL::Cipher.new('AES-128-CBC')
      decipher.decrypt
      decipher.iv  = iv
      decipher.key = secret.encryption_key
      decipher.update(encrypted_message) + decipher.final
    end

    def enforce_ttl?
      @enforce_ttl
    end

    def now
      @now ||= DateTime.now
    end
  end
end
