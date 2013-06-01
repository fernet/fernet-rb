require 'spec_helper'
require 'fernet'

describe Fernet do
  after { Fernet::Configuration.run }

  let(:secret)     { 'JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }
  let(:bad_secret) { 'badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }

  it 'can verify tokens it generates' do
    token = Fernet.generate(secret) do |generator|
      generator.message = 'harold@heroku.com'
    end

    Fernet.verify(secret, token) do |verifier|
      expect(verifier.message).to eq('harold@heroku.com')
    end

    expect(Fernet.verifier(secret, token)).to be_valid
  end

  it 'can generate tokens without a bloc' do
    token = Fernet.generate(secret, 'harold@heroku.com')
    Fernet.verify(secret, token) do |verifier|
      expect(verifier.message).to eq('harold@heroku.com')
    end
  end

  it 'fails with a bad secret' do
    token = Fernet.generate(secret) do |generator|
      generator.message = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(bad_secret, token) do |verifier|
        verifier.message == 'harold@heroku.com'
      end
    ).to be_false
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret, 'harold@heroku.com', now: Time.now - 61)

    expect(
      Fernet.verify(secret, token) do |verifier|
        verifier.ttl = 60
      end
    ).to be_false
  end

  it 'can ignore TTL enforcement' do
    # Make sure the global value is set to true
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
    end

    token = Fernet.generate(secret) do |generator|
      generator.message = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(secret, token, now: Time.now + 9999) do |verifier|
        verifier.enforce_ttl = false
      end
    ).to be_true
  end

  it 'can ignore TTL enforcement via global config' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = false
    end

    token = Fernet.generate(secret) do |generator|
      generator.message = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(secret, token, now: Time.now + 9999999)
    ).to be_true
  end

  it 'encrypts the payload' do
    token = Fernet.generate(secret, 'password1')

    expect(Base64.decode64(token)).not_to match /password1/

    Fernet.verify(secret, token) do |verifier|
      expect(verifier.message).to eq('password1')
    end
  end

  it 'allows overriding enforce_ttl on a verifier' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
      config.ttl = 0
    end
    token = Fernet.generate(secret) do |generator|
      generator.message = 'password1'
    end
    verifier = Fernet.verifier(secret, token)
    verifier.enforce_ttl = false
    expect(verifier.valid?).to be_true
    expect(verifier.message).to eq('password1')
  end

  it 'allows overriding enforce_ttl on verifier block' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
      config.ttl = 0
    end
    token = Fernet.generate(secret) do |generator|
      generator.message = 'password1'
    end
    verifier = Fernet.verifier(secret, token) do |v|
      v.enforce_ttl = false
    end
    expect(verifier.message).to eq('password1')
    expect(verifier.valid?).to be_true
  end
end
