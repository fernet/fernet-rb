require 'spec_helper'
require 'fernet/secret'

describe Fernet::Secret do
  it "expects base64 encoded 32 byte strings" do
    secret = Base64.urlsafe_encode64("A"*32)
    expect do
      Fernet::Secret.new(secret)
    end.to_not raise_error
  end

  it "extracts encryption and signing keys" do
    secret = Base64.urlsafe_encode64("A"*16 + "B"*16)
    fernet_secret = Fernet::Secret.new(secret)
    expect(
      fernet_secret.signing_key
    ).to eq("A"*16)

    expect(
      fernet_secret.encryption_key
    ).to eq("B"*16)
  end

  it "fails loudly when an invalid secret is provided" do
    secret = Base64.urlsafe_encode64("bad")
    expect do
      Fernet::Secret.new(secret)
    end.to raise_error(Fernet::Secret::InvalidSecret)
  end
end
