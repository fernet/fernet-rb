#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'
require_relative 'errors'

module Fernet
  # Public: verifies Fernet Tokens
  class Verifier
    class UnknownTokenVersion < Fernet::Error; end

    attr_reader :token, :enforce_ttl
    attr_accessor :ttl

    # Internal: initializes a Verifier
    #
    # opts - a hash containing
    # * secret             - the secret used to create the token (required) - can be an array of secrets
    # * token              - the fernet token string (required)
    # * enforce_ttl        - whether to enforce TTL, defaults to Configuration.enforce_ttl
    # * ttl                - number of seconds the token is valid
    # * additional_secrets - additional secrets which can be used to decrypt
    #                        the token, useful for credrolls when changing the
    #                        secret.
    def initialize(opts = {})
      @enforce_ttl = opts.has_key?(:enforce_ttl) ? opts[:enforce_ttl] : Configuration.enforce_ttl
      @opts = opts
      create_token!
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
      @token.message.dup.force_encoding(Encoding::UTF_8)
    end

    # Deprecated: returns the token's message
    def data
      puts "[WARNING] data is deprecated. Use message instead"
      message
    end

    # Public: String representation of this verifier, masks the secret to avoid
    #   leaks
    def inspect
      "#<Fernet::Verifier @secret=[masked] @token=#{@token} @message=#{@message.inspect} @ttl=#{@ttl} @enforce_ttl=#{@enforce_ttl}>"
    end
    alias to_s inspect

    # Public: sets the enforce_ttl configuration
    #
    # * val - whether to enforce TTL, defaults to Configuration.enforce_ttl
    def enforce_ttl=(val)
      @enforce_ttl = val
      create_token!
    end

  private
    def create_token!
      secrets = (Array(@opts.fetch(:secret)) + @opts.fetch(:additional_secrets, [])).compact
      if secrets.length > 1
        secret = secrets.find do |secret|
          Token.new(@opts.fetch(:token),
                    secret: secret,
                    enforce_ttl: false).valid?
        end
      else
        secret = secrets.first
      end

      @token = Token.new(@opts.fetch(:token),
                         secret: secret || @opts.fetch(:secret),
                         enforce_ttl: enforce_ttl,
                         ttl: @opts[:ttl],
                         now: @opts[:now])
    end
  end
end
