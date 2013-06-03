#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  class Verifier
    class UnknownTokenVersion < RuntimeError; end

    attr_reader :token
    attr_accessor :ttl, :enforce_ttl

    def initialize(opts = {})
      enforce_ttl = opts.has_key?(:enforce_ttl) ? opts[:enforce_ttl] : Configuration.enforce_ttl
      @token = Token.new(opts.fetch(:token),
                           enforce_ttl: enforce_ttl,
                           ttl: opts[:ttl],
                           now: opts[:now])
      @token.secret = opts.fetch(:secret)
    end

    def valid?
      @token.valid?
    end

    def message
      @token.message
    end

    def data
      puts "[WARNING] data is deprected. Use message instead"
      message
    end

    def inspect
      "#<Fernet::Verifier @secret=[masked] @token=#{@token} @message=#{@message.inspect} @ttl=#{@ttl} @enforce_ttl=#{@enforce_ttl}>"
    end
    alias to_s inspect

  private
    def must_verify?
      @must_verify || @valid.nil?
    end

    def token_recent_enough?
      if enforce_ttl?
        good_till = @issued_at + (ttl.to_f / 24 / 60 / 60)
        (good_till.to_i >= now.to_i) && acceptable_clock_skew?
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

    def enforce_ttl?
      @enforce_ttl
    end

    def now
      @now ||= Time.now
    end
  end
end
