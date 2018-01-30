# encoding: utf-8

require 'spec_helper'
require 'fernet'

describe Fernet do
  after { Fernet::Configuration.run }

  let(:secret)     { 'JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }
  let(:bad_secret) { 'badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }

  it 'can verify tokens it generates' do
    ['harold@heroku.com', '12345', 'weird!@#$%^&*()chars', 'more weird chars §§§§'].each do |plain|
      token = Fernet.generate(secret, plain)

      verifier = Fernet.verifier(secret, token)
      expect(verifier).to be_valid
      expect(verifier.message).to eq(plain)
    end
  end

  it 'fails with a bad secret' do
    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier(bad_secret, token)
    expect(verifier.valid?).to eq(false)
    expect {
      verifier.message
    }.to raise_error Fernet::Token::InvalidToken
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret, 'harold@heroku.com', now: (Time.now - 61))

    verifier = Fernet.verifier(secret, token)
    expect(verifier.valid?).to eq(false)
  end

  it 'can ignore TTL enforcement' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
    end

    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier(secret, token, enforce_ttl: false,
                                              now: Time.now + 9999)
    expect(verifier.valid?).to eq(true)
  end

  it 'can ignore TTL enforcement via global config' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = false
    end

    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier(secret, token, now: Time.now + 999999)
    expect(verifier.valid?).to eq(true)
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
    token = Fernet.generate(secret, 'password1')
    verifier = Fernet.verifier(secret, token, now: Time.now + 999999)
    verifier.enforce_ttl = false
    expect(verifier.valid?).to eq(true)
    expect(verifier.message).to eq('password1')
  end

  it 'verifies the token using one of several supplied keys' do
    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier(bad_secret, token, additional_secrets: [secret])

    expect(verifier).to be_valid
    expect(verifier.message).to eq('harold@heroku.com')
  end

  it 'ignores nil values as additional secrets' do
    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier(bad_secret, token, additional_secrets: [nil])

    expect(verifier.valid?).to eq(false)
    expect {
      verifier.message
    }.to raise_error Fernet::Token::InvalidToken
  end

  it 'accepts multiple secrets in an array to verify' do
    token = Fernet.generate(secret, 'harold@heroku.com')

    verifier = Fernet.verifier([bad_secret, secret], token)

    expect(verifier).to be_valid
    expect(verifier.message).to eq('harold@heroku.com')
  end
end
