# frozen_string_literal: false

# Record-level signing and verification (spec/provenance.md).
#
# The signature is computed over the record's canonical identity-bearing bytes
# (the RFC 8785 form with id and signature removed - exactly the bytes that are
# hashed for the record's identifier), so verification needs nothing but the
# record itself. Ed25519 is deterministic (RFC 8032): re-signing the same record
# with the same key yields the same signature, so re-submission is idempotent.

require_relative "ed25519"
require_relative "canonical"

module Causalontology
  module Signing
    module_function

    # Hex encoding of a binary string.
    def bin_to_hex(s)
      s.unpack1("H*")
    end

    # Binary decoding of a hex string, or nil when the text is not clean hex.
    def hex_to_bin(hex)
      return nil unless hex.is_a?(String)
      return nil unless hex.length.even? && hex.match?(/\A\h*\z/)
      [hex].pack("H*")
    end

    # [secret, "ed25519:<hex>"] from a 32-byte seed.
    def keypair_from_seed(seed32)
      public_key = Ed25519.secret_to_public(seed32)
      [seed32, "ed25519:" + bin_to_hex(public_key)]
    end

    # Return the record completed with its id and Ed25519 signature.
    def sign_record(record, secret, kind = nil)
      kind ||= Canonical.infer_kind(record)
      body = record.dup
      body.delete("signature")
      message = Canonical.canonicalize(body, kind)
      signature = bin_to_hex(Ed25519.sign(secret, message))
      out = body.dup
      out["id"] = Canonical.identify(body, kind)
      out["signature"] = signature
      out
    end

    # The hex of the key the record must verify against: a succession is
    # signed by the predecessor key; every other record by its source.
    def signer_key_hex(record, kind)
      field = kind == "succession" ? "predecessor" : "source"
      value = record[field] || ""
      return nil unless value.is_a?(String) && value.start_with?("ed25519:")
      value.split(":", 2)[1]
    end

    # True iff the record's signature verifies against its own key field.
    def verify_record(record, kind = nil)
      kind ||= Canonical.infer_kind(record)
      sig_hex = record["signature"]
      key_hex = signer_key_hex(record, kind)
      return false if sig_hex.nil? || sig_hex.empty?
      return false if key_hex.nil? || key_hex.empty?
      public_key = hex_to_bin(key_hex)
      signature = hex_to_bin(sig_hex)
      return false if public_key.nil? || signature.nil?
      body = record.dup
      body.delete("signature")
      message = Canonical.canonicalize(body, kind)
      Ed25519.verify(public_key, message, signature)
    end
  end
end
