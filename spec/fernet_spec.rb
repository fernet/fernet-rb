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

    verifier = Fernet.verifier(secret, token)
    expect(verifier).to be_valid
    expect(verifier.message).to eq('harold@heroku.com')
  end

  it 'can generate tokens without a block' do
    token = Fernet.generate(secret, 'harold@heroku.com')
    verifier = Fernet.verifier(secret, token)
    expect(verifier).to be_valid
    expect(verifier.message).to eq('harold@heroku.com')
  end

  it 'fails with a bad secret' do
    token = Fernet.generate(secret) do |generator|
      generator.message = 'harold@heroku.com'
    end

    verifier = Fernet.verifier(bad_secret, token)
    expect(verifier.valid?).to be_false
    expect {
      verifier.message
    }.to raise_error
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret, 'harold@heroku.com', now: (Time.now - 61))

    verifier = Fernet.verifier(secret, token)
    expect(verifier.valid?).to be_false
  end

  it 'can ignore TTL enforcement' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
    end

    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier(secret, token, enforce_ttl: false,
                                              now: Time.now + 9999)
    expect(verifier.valid?).to be_true
  end

  it 'can ignore TTL enforcement via global config' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = false
    end

    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier(secret, token, now: Time.now + 999999)
    expect(verifier.valid?).to be_true
  end

  it 'does not send the message in plain text' do
    token = Fernet.generate(secret, 'password1')

    expect(Base64.urlsafe_decode64(token)).not_to match /password1/
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
end
