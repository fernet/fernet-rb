# encoding: utf-8

require 'spec_helper'
require 'fernet'

describe Fernet do
  after { Fernet::Configuration.run }

  let(:secret128)  { 'JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }
  let(:secret192)  { 'HE_GGEDrDA3L2GJBaoFPkQseOzSjAi1aPSTil0PL5p5eJwYHuvvQMPRphvTW-EUl' }
  let(:secret256)  { 'iad7Z_H9a0BGsWoNz-7SbDon9URcuCECWb0QbTJk2MrD8_DWQvShFXUB_MxAkSly6WbzO6DmfTF_prBYV5NL7A==' }
  let(:bad_secret) { 'badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }

  it 'can verify tokens it generates for AES128' do
    ['harold@heroku.com', '12345', 'weird!@#$%^&*()chars', 'more weird chars §§§§'].each do |plain|
      token = Fernet.generate(secret128, plain)

      verifier = Fernet.verifier(secret128, token)
      expect(verifier).to be_valid
      expect(verifier.message).to eq(plain)
    end
  end

  it 'can verify tokens it generates for AES192' do
    ['harold@heroku.com', '12345', 'weird!@#$%^&*()chars', 'more weird chars §§§§'].each do |plain|
      token = Fernet.generate(secret192, plain)

      verifier = Fernet.verifier(secret192, token)
      expect(verifier).to be_valid
      expect(verifier.message).to eq(plain)
    end
  end

  it 'can verify tokens it generates for AES256' do
    ['harold@heroku.com', '12345', 'weird!@#$%^&*()chars', 'more weird chars §§§§'].each do |plain|
      token = Fernet.generate(secret256, plain)

      verifier = Fernet.verifier(secret256, token)
      expect(verifier).to be_valid
      expect(verifier.message).to eq(plain)
    end
  end

  it 'fails with a bad secret' do
    token = Fernet.generate(secret128, 'harold@heroku.com')

    verifier = Fernet.verifier(bad_secret, token)
    expect(verifier.valid?).to eq(false)
    expect {
      verifier.message
    }.to raise_error Fernet::Token::InvalidToken
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret128, 'harold@heroku.com', now: (Time.now - 61))

    verifier = Fernet.verifier(secret128, token)
    expect(verifier.valid?).to eq(false)
  end

  it 'can ignore TTL enforcement' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
    end

    token = Fernet.generate(secret128, 'harold@heroku.com')

    verifier = Fernet.verifier(secret128, token, enforce_ttl: false,
                                              now: Time.now + 9999)
    expect(verifier.valid?).to eq(true)
  end

  it 'can ignore TTL enforcement via global config' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = false
    end

    token = Fernet.generate(secret128, 'harold@heroku.com')

    verifier = Fernet.verifier(secret128, token, now: Time.now + 999999)
    expect(verifier.valid?).to eq(true)
  end

  it 'does not send the message in plain text' do
    token = Fernet.generate(secret128, 'password1')

    expect(Base64.urlsafe_decode64(token)).not_to match /password1/
  end

  it 'allows overriding enforce_ttl on a verifier' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
      config.ttl = 0
    end
    token = Fernet.generate(secret128, 'password1')
    verifier = Fernet.verifier(secret128, token, now: Time.now + 999999)
    verifier.enforce_ttl = false
    expect(verifier.valid?).to eq(true)
    expect(verifier.message).to eq('password1')
  end
end
