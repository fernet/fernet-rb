require 'spec_helper'
require 'fernet/bit_packing'

describe Fernet::BitPacking do
  VALUE_TO_BYTES = {
    0x0000000000000000 => [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    0x00000000000000FF => [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF ],
    0x000000FF00000000 => [ 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00 ],
    0x00000000FF000000 => [ 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00 ],
    0xFF00000000000000 => [ 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
    0xFFFFFFFFFFFFFFFF => [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ]
  }

  def self.pretty(bytea)
    "0x#{bytea.map { |b| sprintf("%.2x", b) }.join}"
  end

  def self.bytestr(bytea)
    bytea.map(&:chr).join
  end

  VALUE_TO_BYTES.each do |value, bytes|
    pretty_bytes = pretty(bytes).rjust(20)
    pretty_val = value.to_s.rjust(20)
    bytestr = bytestr(bytes)
    it "should encode #{pretty_val} to #{pretty_bytes}" do
      expect(Fernet::BitPacking.pack_int64_bigendian(value)).to eq(bytestr)
    end

    # N.B.: we have two extra spaces in the spec description for
    # aligned formatting w.r.t. the 'encode' specs
    it "should decode #{pretty_bytes} to #{pretty_val}" do
      expect(Fernet::BitPacking.unpack_int64_bigendian(bytestr)).to eq(value)
    end
  end
end
