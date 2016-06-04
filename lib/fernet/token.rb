# encoding UTF-8
require 'base64'
require 'valcro'
require_relative 'errors'

module Fernet
  # Internal: encapsulates a fernet token structure and validation
  class Token
    include Valcro

    class InvalidToken < Fernet::Error; end

    # Internal: the default token version
    DEFAULT_VERSION = 0x80.freeze
    # Internet: mapping from key size to version byte
    VALID_VERSIONS = { 128 => 0x80, 192 => 0xA0, 256 => 0xC0 }.freeze
    # Internal: max allowed clock skew for calculating TTL
    MAX_CLOCK_SKEW  = 60.freeze

    # Internal: initializes a Token object
    #
    # token - the string representation of this token
    # opts  - a has containing
    # * secret       - the secret, optionally base 64 encoded (required)
    # * enforce_ttl  - whether to enforce TTL upon validation. Defaults to
    #                  value set in Configuration.enforce_ttl
    # * ttl          - number of seconds token is valid, defaults to
    #                  Configuration.ttl
    def initialize(token, opts = {})
      @token       = token
      begin
        version_byte = version
      rescue
        version_byte = DEFAULT_VERSION
      end
      key_bits, _ = VALID_VERSIONS.rassoc(version_byte) || [ 128, 0 ]
      @secret      = Secret.new(opts.fetch(:secret), key_bits)
      @enforce_ttl = opts.fetch(:enforce_ttl) { Configuration.enforce_ttl }
      @ttl         = opts[:ttl] || Configuration.ttl
      @now         = opts[:now]
    end

    # Internal: returns the token as a string
    def to_s
      @token
    end

    # Internal: Validates this token and returns true if it's valid
    #
    # Returns a boolean set to true if it's valid, false otherwise
    def valid?
      validate
      super
    end

    # Internal: returns the decrypted message in this token
    #
    # Raises InvalidToken if it cannot be decrypted or is invalid
    #
    # Returns a string containing the original message in plain text
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

    # Internal: generates a Fernet Token
    #
    # opts - a hash containing
    # * secret   - a string containing the secret, optionally base64 encoded
    # * message  - the message in plain text
    # * key_bits - number of bits in the AES key
    def self.generate(opts)
      unless opts[:secret]
        raise ArgumentError, 'Secret not provided'
      end
      key_bits = opts[:key_bits] || 128
      secret = Secret.new(opts.fetch(:secret), key_bits)
      encrypted_message, iv = Encryption.encrypt(
        key:     secret.encryption_key,
        message: opts[:message],
        iv:      opts[:iv]
      )
      issued_timestamp = (opts[:now] || Time.now).to_i

      version = opts[:version] || VALID_VERSIONS[key_bits] || DEFAULT_VERSION
      payload = [version].pack("C") +
        BitPacking.pack_int64_bigendian(issued_timestamp) +
        iv +
        encrypted_message
      mac = OpenSSL::HMAC.digest('sha256', secret.signing_key, payload)
      new(Base64.urlsafe_encode64(payload + mac), secret: opts.fetch(:secret))
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
        elsif enforce_ttl? && !issued_recent_enough?
          errors.add :issued_timestamp, "is too far in the past: token expired"
        else
          unless signatures_match?
            errors.add :signature, "does not match"
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
      !decoded_token.nil?
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
      VALID_VERSIONS.rassoc(version).nil?
    end

    def enforce_ttl?
      @enforce_ttl
    end

    def now
      @now || Time.now
    end
  end
end
