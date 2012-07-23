require 'base64'
require 'json'
require 'openssl'
require 'date'

module Fernet
  class Generator
    attr_accessor :data

    def initialize(secret)
      @secret = secret
    end

    def generate
      yield self if block_given?
      data.merge!(issued_at: DateTime.now)

      mac = OpenSSL::HMAC.hexdigest('sha256', JSON.dump(data), secret)
      Base64.urlsafe_encode64(JSON.dump(data.merge(signature: mac)))
    end

    def inspect
      "#<Fernet::Generator @secret=[masked] @data=#{@data.inspect}>"
    end
    alias to_s inspect

    def data
      @data ||= {}
    end

  private
    attr_reader :secret
  end
end
