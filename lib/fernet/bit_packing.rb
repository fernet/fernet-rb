module Fernet
  module BitPacking
    extend self

    # N.B. Ruby 1.9.2 and below silently ignore endianness specifiers in
    # packing/unpacking format directives; we work around it with this
    # TODO: Use pack/unpack('Q>') in 1.9.3 and up

    def pack_int64_bigendian(value)
      (0..7).map { |index| (value >> (index * 8)) & 0xFF }.reverse.map(&:chr).join
    end

    def unpack_int64_bigendian(bytes)
      bytes.each_byte.to_a.reverse.each_with_index
        .reduce(0) { |val, (byte, index)| val | (byte << (index * 8)) }
    end
  end
end
