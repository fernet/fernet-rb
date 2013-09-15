#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  # Public: verifies Fernet Tokens
  class Verifier
    class UnknownTokenVersion < RuntimeError; end

    attr_reader :token
    attr_accessor :ttl, :enforce_ttl

    # Internal: initializes a Verifier
    #
    # opts - a hash containing
    #   secret: the secret used to create the token (required)
    #   token: the fernet token string (required)
    #   enforce_ttl: whether to enforce TTL, defaults to Configuration.enforce_ttl
    #   ttl: number of seconds the token is valid
    def initialize(opts = {})
      enforce_ttl = opts.has_key?(:enforce_ttl) ? opts[:enforce_ttl] : Configuration.enforce_ttl
      @token = Token.new(opts.fetch(:token),
                           secret: opts.fetch(:secret),
                           enforce_ttl: enforce_ttl,
                           ttl: opts[:ttl],
                           now: opts[:now])
    end

    # Public: whether the verifier is valid. A verifier is valid if it's token
    #   is valid.
    #
    # Returns a boolean set to true if the token is valid, false otherwise
    def valid?
      @token.valid?
    end

    # Public: Returns the token's message
    def message
      @token.message
    end

    # Deprecated: returns the token's message
    def data
      puts "[WARNING] data is deprected. Use message instead"
      message
    end

    # Public: String representation of this verifier, masks the secret to avoid leaks.
    def inspect
      "#<Fernet::Verifier @secret=[masked] @token=#{@token} @message=#{@message.inspect} @ttl=#{@ttl} @enforce_ttl=#{@enforce_ttl}>"
    end
    alias to_s inspect

  private
    def must_verify?
      @must_verify || @valid.nil?
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

    def now
      @now ||= Time.now
    end
  end
end
