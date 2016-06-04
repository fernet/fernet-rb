require 'spec_helper'
require 'fernet'
require 'json'

describe Fernet::Token, 'validation' do
  let(:secret128) { 'odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=' }
  let(:secret192) { 'HE_GGEDrDA3L2GJBaoFPkQseOzSjAi1aPSTil0PL5p5eJwYHuvvQMPRphvTW-EUl' }
  let(:secret256) { 'iad7Z_H9a0BGsWoNz-7SbDon9URcuCECWb0QbTJk2MrD8_DWQvShFXUB_MxAkSly6WbzO6DmfTF_prBYV5NL7A==' }

  it 'is invalid with a bad MAC signature' do
    generated = Fernet::Token.generate(secret: secret128,
                                       message: 'hello')

    bogus_hmac = "1" * 32
    allow(Fernet::Encryption).to receive(:hmac_digest).and_return(bogus_hmac)

    token = Fernet::Token.new(generated.to_s, secret: secret128)

    expect(token.valid?).to eq(false)
    expect(token.errors[:signature]).to include("does not match")
  end

  it 'is invalid if too old' do
    generated = Fernet::Token.generate(secret: secret128,
                                       message: 'hello',
                                       now: Time.now - 61)
    token = Fernet::Token.new(generated.to_s, enforce_ttl: true,
                                              ttl: 60,
                                              secret: secret128)
    expect(token.valid?).to eq(false)
    expect(token.errors[:issued_timestamp]).to include("is too far in the past: token expired")
  end

  it 'is invalid with a large clock skew' do
    generated = Fernet::Token.generate(secret:  secret128,
                                       message: 'hello',
                                       now:     Time.at(Time.now.to_i + 61))
    token = Fernet::Token.new(generated.to_s, secret: secret128)

    expect(token.valid?).to eq(false)
    expect(token.errors[:issued_timestamp]).to include("is too far in the future")
  end

  it 'is invalid with bad base64' do
    token = Fernet::Token.new('bad', secret: secret128)

    expect(token.valid?).to eq(false)
    expect(token.errors[:token]).to include("invalid base64")
  end

  it 'is invalid with an unknown token version' do
    invalid1 = Fernet::Token.generate(message: 'message', version: 0x00, secret: secret128)
    invalid2 = Fernet::Token.generate(message: 'message', version: 0x81, secret: secret128)
    valid128 = Fernet::Token.generate(message: 'message', secret: secret128)
    valid192 = Fernet::Token.generate(message: 'message', secret: secret192, key_bits: 192)
    valid256 = Fernet::Token.generate(message: 'message', secret: secret256, key_bits: 256)

    [invalid1, invalid2].each do |token|
      expect(token.valid?).to eq(false)
      expect(token.errors[:version]).to include("is unknown")
    end
    expect(valid128.valid?).to eq(true)
    expect(valid192.valid?).to eq(true)
    expect(valid256.valid?).to eq(true)
  end

  it 'is invalid with bad base64 encodings' do
    token = Fernet::Token.generate(message: 'message', secret: secret128)
    invalid = Fernet::Token.new("\n#{token}", secret: secret128)

    ["\n#{token}", "#{token} ", "#{token}+",
      token.to_s.gsub(/(.)$/, "1"),
      token.to_s.gsub(/(.)$/, "+"),
      token.to_s.gsub(/(.)$/, "\\"),
    ].each do |invalid_string|
      invalid = Fernet::Token.new(invalid_string, secret: secret128)
      expect(invalid.valid?).to be(false)
    end
  end
end

describe Fernet::Token, 'message' do
  let(:secret128) { 'odN/0Yu+Pwp3oIvvG8OiE5w4LsLrqfWYRb3knQtSyKI=' }
  let(:secret192) { 'HE_GGEDrDA3L2GJBaoFPkQseOzSjAi1aPSTil0PL5p5eJwYHuvvQMPRphvTW-EUl' }
  let(:secret256) { 'iad7Z_H9a0BGsWoNz-7SbDon9URcuCECWb0QbTJk2MrD8_DWQvShFXUB_MxAkSly6WbzO6DmfTF_prBYV5NL7A==' }

  it 'refuses to decrypt if invalid' do
    generated = Fernet::Token.generate(secret:  secret128,
                                       message: 'hello',
                                       now:     Time.now + 61)
    token = Fernet::Token.new(generated.to_s, secret: secret128)

    !token.valid? or raise "invalid token"

    expect {
      token.message
    }.to raise_error Fernet::Token::InvalidToken,
      /issued_timestamp is too far in the future/
  end

  it 'gives back the original message in plain text for AES128' do
    token = Fernet::Token.generate(secret: secret128,
                                   message: 'hello')
    token.valid? or raise "invalid token"

    expect(token.message).to eq('hello')
  end

  it 'gives back the original message in plain text for AES192' do
    token = Fernet::Token.generate(secret: secret192,
                                   key_bits: 192,
                                   message: 'hello')
    token.valid? or raise "invalid token"

    expect(token.message).to eq('hello')
  end

  it 'gives back the original message in plain text for AES256' do
    token = Fernet::Token.generate(secret: secret256,
                                   key_bits: 256,
                                   message: 'hello')
    token.valid? or raise "invalid token"

    expect(token.message).to eq('hello')
  end

  it 'correctly handles an empty message' do
    token = Fernet::Token.generate(secret: secret128,
                                   message: '')
    token.valid? or raise "invalid token"

    expect(token.message).to eq('')
  end
end
