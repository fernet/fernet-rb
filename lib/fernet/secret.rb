module Fernet
  class Secret
    def initialize(secret, encrypt)
      @secret  = secret
      @encrypt = encrypt
    end

    def encryption_key
      decoded_secret.slice(decoded_secret.size/2, decoded_secret.size)
    end

    def signing_key
      if @encrypt
        decoded_secret.slice(0, decoded_secret.size/2)
      else
        decoded_secret
      end
    end

  private
    def decoded_secret
      @decoded_secret ||= Base64.decode64(@secret)
    end
  end
end
