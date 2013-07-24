# encoding UTF-8
require 'base64'
require 'valcro'

module Fernet
  class Token
    include Valcro

    class InvalidToken < StandardError; end

    DEFAULT_VERSION = 0x80.freeze
    MAX_CLOCK_SKEW  = 60.freeze

    def initialize(token, opts = {})
      @token       = token
      @enforce_ttl = opts.fetch(:enforce_ttl) { Configuration.enforce_ttl }
      @ttl         = opts[:ttl] || Configuration.ttl
      @now         = opts[:now]
    end

    def to_s
      @token
    end

    def secret=(secret)
      @secret = Secret.new(secret)
    end

    def valid?
      validate
      super
    end

    def message
      if valid?
        begin
          Encryption.decrypt(key: @secret.encryption_key,
                             ciphertext: encrypted_message,
                             iv: iv)
        rescue OpenSSL::Cipher::CipherError
          raise InvalidToken, "bad decrypt"
        end
      else
        raise InvalidToken, error_messages
      end
    end

    def self.generate(params)
      unless params[:secret]
        raise ArgumentError, 'Secret not provided'
      end
      secret = Secret.new(params[:secret])
      encrypted_message, iv = Encryption.encrypt(key:     secret.encryption_key,
                                                 message: params[:message],
                                                 iv:      params[:iv])
      issued_timestamp = (params[:now] || Time.now).to_i

      payload = [DEFAULT_VERSION].pack("C") +
        BitPacking.pack_int64_bigendian(issued_timestamp) +
        iv +
        encrypted_message
      mac = OpenSSL::HMAC.digest('sha256', secret.signing_key, payload)
      new(Base64.urlsafe_encode64(payload + mac))
    end

  private
    def decoded_token
      @decoded_token ||= Base64.urlsafe_decode64(@token)
    end

    def version
      decoded_token.chr.unpack("C").first
    end

    def received_signature
      decoded_token[(decoded_token.length - 32), 32]
    end

    def issued_timestamp
      BitPacking.unpack_int64_bigendian(decoded_token[1, 8])
    end

    def iv
      decoded_token[9, 16]
    end

    def encrypted_message
      decoded_token[25..(decoded_token.length - 33)]
    end

    validate do
      if valid_base64?
        if unknown_token_version?
          errors.add :version, "is unknown"
        else
          unless signatures_match?
            errors.add :signature, "does not match"
          end
          if enforce_ttl? && !issued_recent_enough?
            errors.add :issued_timestamp, "is too far in the past: token expired"
          end
          if unacceptable_clock_slew?
            errors.add :issued_timestamp, "is too far in the future"
          end
          unless ciphertext_multiple_of_block_size?
            errors.add :ciphertext, "is not a multiple of block size"
          end
        end
      else
        errors.add(:token, "invalid base64")
      end
    end

    def regenerated_mac
      Encryption.hmac_digest(@secret.signing_key, signing_blob)
    end

    def signing_blob
      [version].pack("C") +
        BitPacking.pack_int64_bigendian(issued_timestamp) +
        iv +
        encrypted_message
    end

    def valid_base64?
      decoded_token
      true
    rescue ArgumentError
      false
    end

    def signatures_match?
      regenerated_bytes = regenerated_mac.bytes.to_a
      received_bytes    = received_signature.bytes.to_a
      received_bytes.inject(0) do |accum, byte|
        accum |= byte ^ regenerated_bytes.shift
      end.zero?
    end

    def issued_recent_enough?
      good_till = issued_timestamp + @ttl
      good_till >= now.to_i
    end

    def unacceptable_clock_slew?
      issued_timestamp >= (now.to_i + MAX_CLOCK_SKEW)
    end

    def ciphertext_multiple_of_block_size?
      (encrypted_message.size % Encryption::AES_BLOCK_SIZE).zero?
    end

    def unknown_token_version?
      DEFAULT_VERSION != version
    end

    def enforce_ttl?
      @enforce_ttl
    end

    def now
      @now || Time.now
    end
  end
end
