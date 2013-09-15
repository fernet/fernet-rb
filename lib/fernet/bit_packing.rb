module Fernet
  # Internal: wrappers used for consistent bit packing across rubies
  #
  # Ruby 1.9.2 and below silently ignore endianness specifiers in
  # packing/unpacking format directives
  module BitPacking
    extend self

    # Internal - packs a value as a big endian, 64 bit integer
    #
    # value - a byte sequence as a string
    #
    # Returns array containing each value
    def pack_int64_bigendian(value)
      (0..7).map { |index| (value >> (index * 8)) & 0xFF }.reverse.map(&:chr).join
    end

    # Internal - unpacks a string of big endian, 64 bit integers
    #
    # bytes - an array of ints
    #
    # Returns the original byte sequence as a string
    def unpack_int64_bigendian(bytes)
      bytes.each_byte.to_a.reverse.each_with_index.
        reduce(0) { |val, (byte, index)| val | (byte << (index * 8)) }
    end
  end
end
