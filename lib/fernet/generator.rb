#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  class Generator
    attr_accessor :message

    def initialize(opts)
      @secret  = Secret.new(opts.fetch(:secret))
      @message = opts[:message]
      @iv      = opts[:iv]
      @now     = opts[:now]
    end

    def generate
      yield self if block_given?
      encrypted_message = encrypt
      issued_timestamp = now.to_i
      payload = [Fernet::TOKEN_VERSION].pack("C") +
        BitPacking.pack_int64_bigendian(issued_timestamp) +
        @iv + encrypted_message
      mac = OpenSSL::HMAC.digest('sha256', secret.signing_key, payload)
      Base64.urlsafe_encode64(payload + mac)
    end

    def inspect
      "#<Fernet::Generator @secret=[masked] @message=#{@message.inspect}>"
    end
    alias to_s inspect

    def data=(message)
      puts "[WARNING] 'data' is deprecated, use 'message' instead"
      @message = message
    end

  private
    attr_reader :secret

    def encrypt
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      @iv ||= cipher.random_iv
      cipher.iv  = @iv
      cipher.key = secret.encryption_key
      cipher.update(self.message) + cipher.final
    end

    def now
      @now ||= Time.now
    end

  end
end
