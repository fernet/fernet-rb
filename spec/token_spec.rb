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

    token = Fernet::Token.new(generated.to_s, secret: secret)

    expect(token.valid?).to eq(false)
    expect(token.errors[:signature]).to include("does not match")
  end

  it 'is invalid if too old' do
    generated = Fernet::Token.generate(secret: secret,
                                       message: 'hello',
                                       now: Time.now - 61)
    token = Fernet::Token.new(generated.to_s, enforce_ttl: true,
                                              ttl: 60,
                                              secret: secret)
    expect(token.valid?).to eq(false)
    expect(token.errors[:issued_timestamp]).to include("is too far in the past: token expired")
  end

  it 'is invalid with a large clock skew' do
    generated = Fernet::Token.generate(secret:  secret,
                                       message: 'hello',
                                       now:     Time.at(Time.now.to_i + 61))
    token = Fernet::Token.new(generated.to_s, secret: secret)

    expect(token.valid?).to eq(false)
    expect(token.errors[:issued_timestamp]).to include("is too far in the future")
  end

  it 'is invalid with bad base64' do
    token = Fernet::Token.new('bad', secret: secret)

    expect(token.valid?).to eq(false)
    expect(token.errors[:token]).to include("invalid base64")
  end

  it 'is invalid with an unknown token version' do
    invalid1 = Fernet::Token.generate(message: 'message', version: 0x00, secret: secret)
    invalid2 = Fernet::Token.generate(message: 'message', version: 0x81, secret: secret)
    valid    = Fernet::Token.generate(message: 'message', secret: secret)

    [invalid1, invalid2].each do |token|
      expect(token.valid?).to eq(false)
      expect(token.errors[:version]).to include("is unknown")
    end
    expect(valid.valid?).to eq(true)
  end

  it 'is invalid with bad base64 encodings' do
    token = Fernet::Token.generate(message: 'message', secret: secret)
    invalid = Fernet::Token.new("\n#{token}", secret: secret)

    ["\n#{token}", "#{token} ", "#{token}+",
      token.to_s.gsub(/(.)$/, "1"),
      token.to_s.gsub(/(.)$/, "+"),
      token.to_s.gsub(/(.)$/, "\\"),
    ].each do |invalid_string|
      invalid = Fernet::Token.new(invalid_string, secret: secret)
      expect(invalid.valid?).to be(false)
    end
  end
end

describe Fernet::Token, 'message' do
  let(:secret) { 'odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=' }
  it 'refuses to decrypt if invalid' do
    generated = Fernet::Token.generate(secret:  secret,
                                       message: 'hello',
                                       now:     Time.now + 61)
    token = Fernet::Token.new(generated.to_s, secret: secret)

    !token.valid? or raise "invalid token"

    expect {
      token.message
    }.to raise_error Fernet::Token::InvalidToken,
      /issued_timestamp is too far in the future/
  end

  it 'gives back the original message in plain text' do
    token = Fernet::Token.generate(secret: secret,
                                   message: 'hello')
    token.valid? or raise "invalid token"

    expect(token.message).to eq('hello')
  end
end
