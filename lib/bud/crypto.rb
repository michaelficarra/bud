require 'openssl'


module Bud
  module Crypto

    def hmac key, message
      sha = OpenSSL::Digest::SHA256.new
      blocksize = 64 # SHA256 uses a 64 byte (512 bit) block size

      def xor str0, str1 # assuming strings are of equal length
        b0 = str0.bytes.to_a
        b1 = str1.bytes.to_a
        result = []
        b0.each_with_index do |b, i|
          result << (b ^ b1[i]).chr
        end
        result.join ''
      end

      if key.length > blocksize
        key = sha.update(key).to_s
        sha.reset
      end
      if key.length < blocksize
        key += 0.chr * (blocksize - key.length)
      end

      o_key_pad = xor key, (92.chr * blocksize)
      i_key_pad = xor key, (54.chr * blocksize)

      hash = sha.update(i_key_pad).update(message).to_s
      sha.reset
      sha.update(o_key_pad).update(hash).to_s
    end

    class SignedUnit

      attr_reader :values, :signature

      def initialize private_key, values
        @values = values
        sha = OpenSSL::Digest::SHA256.new
        hash = (sha << values.to_msgpack).to_s
        rsa = OpenSSL::PKey::RSA.new private_key
        @signature = rsa.private_encrypt hash
      end

      def to_s
        "{|(#{self.class.name}) #{@values.collect{|v| v.inspect}.join ', '} |}"
      end

      def inspect *args; to_s *args; end

      def to_msgpack *args
        Hash[
          'class'     => self.class.name,
          'message'   => @values,
          'signature' => @signature
        ].to_msgpack *args
      end

      def self.verify public_key, signed_unit
        rsa = OpenSSL::PKey::RSA.new public_key
        sha = OpenSSL::Digest::SHA256.new
        begin
          given_hash = rsa.public_decrypt signed_unit.signature
        rescue Exception => e
          return false
        end
        hash = (sha << signed_unit.values.to_msgpack).to_s
        given_hash == hash
      end
    end

    class SymmetricallyEncryptedUnit

      attr_reader :encrypted, :iv

      def initialize symmetric_key, values
        aes = OpenSSL::Cipher.new 'AES256'
        symmetric_key *= 2 while symmetric_key.length < 1024
        @iv = aes.encrypt.random_iv
        aes.key = symmetric_key
        aes.update values.to_msgpack
        @encrypted = aes.final
      end

      def to_s
        "{|(EncryptedUnit) \"#{@encrypted[0..6].inspect[1...-1]}...\" |}"
      end

      def inspect *args; to_s *args; end

      def to_msgpack *args
        Hash[
          'class'   => self.class.name,
          'iv'      => @iv,
          'message' => @encrypted
        ].to_msgpack *args
      end

      def self.decrypt symmetric_key, encrypted_unit
        aes = OpenSSL::Cipher.new 'AES256'
        symmetric_key *= 2 while symmetric_key.length < 1024
        aes.decrypt
        aes.key = symmetric_key
        aes.iv = encrypted_unit.iv
        aes.update encrypted_unit.encrypted
        MessagePack.unpack aes.final
      end
    end


    # intentional helpers

    def sign key, values
      SignedUnit.new key, values
    end

    def enc key, values
      SymmetricallyEncryptedUnit.new key, values
    end


    # client/server message patterns
    # NOTE: these don't work yet, they're just placeholders

    def send_hmac key, message
      [Hash[
        :message, message,
        :signature, hmac(key, message)
      ]]
    end

    def recv_hmac key, recvd
      msg = recvd[:message]
      sig = recvd[:signature]
      msg if sig == hmac(key, message)
    end
  end

  include Bud::Crypto
end


#privk = OpenSSL::PKey::RSA.generate 2048
#pubk = privk.public_key
#privk = privk.to_s


#puts signed = (sign privk, test_data = [[0, 1, 2], :a, 'b'])
#puts SignedUnit.verify pubk, signed
#puts encrypted = (enc 'secret-key', test_data)
#puts (SymmetricallyEncryptedUnit.decrypt 'secret-key', encrypted).inspect
