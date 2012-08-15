module Fernet
  class Secret
    def initialize(secret, encrypt)
      @secret  = secret
      @encrypt = encrypt
    end

    def encryption_key
      @secret.slice(@secret.size/2, @secret.size)
    end

    def signing_key
      if @encrypt
        @secret.slice(0, @secret.size/2)
      else
        @secret
      end
    end
  end
end
