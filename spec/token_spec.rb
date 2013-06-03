require 'spec_helper'
require 'fernet'
require 'json'

describe Fernet::Token, 'validation' do
  let(:secret) { 'odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=' }
  it 'is invalid with a bad MAC signature' do
    generated = Fernet::Token.generate(secret: secret,
                                       message: 'hello')

    bogus_hmac = "1" * 32
    Fernet::Encryption.stub(hmac_digest: bogus_hmac)

    token = Fernet::Token.new(generated.to_s)
    token.secret = secret

    expect(token.valid?).to be_false
    expect(token.errors[:signature]).to include("does not match")
  end

  it 'is invalid if too old' do
    generated = Fernet::Token.generate(secret: secret,
                                       message: 'hello',
                                       now: Time.now - 61)
    token = Fernet::Token.new(generated.to_s, enforce_ttl: true,
                                              ttl: 60)
    token.secret = secret

    expect(token.valid?).to be_false
    expect(token.errors[:issued_timestamp]).to include("is too far in the past: token expired")
  end

  it 'is invalid with a large clock skew' do
    generated = Fernet::Token.generate(secret:  secret,
                                       message: 'hello',
                                       now:     Time.at(Time.now.to_i + 61))
    token = Fernet::Token.new(generated.to_s)
    token.secret = secret

    expect(token.valid?).to be_false
    expect(token.errors[:issued_timestamp]).to include("is too far in the future")
  end

  it 'is invalid with bad base64' do
    token = Fernet::Token.new('bad')
    token.secret = secret

    expect(token.valid?).to be_false
    expect(token.errors[:token]).to include("invalid base64")
  end

  it 'is invalid with an unknown token version' do
    token  = Fernet::Token.new(Base64.urlsafe_encode64("xxxxxx"))

    expect(token.valid?).to be_false
    expect(token.errors[:version]).to include("is unknown")
  end
end

describe Fernet::Token, 'message' do
  let(:secret) { 'odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=' }
  it 'refuses to decrypt if invalid' do
    generated = Fernet::Token.generate(secret:  secret,
                                       message: 'hello',
                                       now:     Time.now + 61)
    token = Fernet::Token.new(generated.to_s)
    token.secret = secret

    !token.valid? or raise "invalid token"

    expect {
      token.message
    }.to raise_error Fernet::Token::InvalidToken,
      /issued_timestamp is too far in the future/
  end

  it 'gives back the original message in plain text' do
    token = Fernet::Token.generate(secret: secret,
                                   message: 'hello')
    token.secret = secret
    token.valid? or raise "invalid token"

    expect(token.message).to eq('hello')
  end
end
