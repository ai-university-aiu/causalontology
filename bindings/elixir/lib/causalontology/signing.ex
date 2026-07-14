defmodule Causalontology.Signing do
  @moduledoc """
  Record-level signing and verification (spec/provenance.md).

  The signature is computed over the record's canonical identity-bearing bytes
  (the RFC 8785 form with id and signature removed - exactly the bytes that are
  hashed for the record's identifier), so verification needs nothing but the
  record itself. Ed25519 is deterministic (RFC 8032): re-signing the same record
  with the same key yields the same signature, so re-submission is idempotent.

  Ed25519 comes from OTP's `:crypto` (`:eddsa` / `:ed25519`) — no Hex
  dependencies.
  """

  alias Causalontology.Canonical

  @doc "{secret, \"ed25519:<hex>\"} from a 32-byte seed."
  def keypair_from_seed(seed32) when is_binary(seed32) and byte_size(seed32) == 32 do
    # :crypto.generate_key/3 returns {PublicKey, PrivateKey} binaries.
    {public, _private} = :crypto.generate_key(:eddsa, :ed25519, seed32)
    {seed32, "ed25519:" <> Base.encode16(public, case: :lower)}
  end

  @doc "Return the record completed with its id and Ed25519 signature."
  def sign_record(record, secret, kind \\ nil) do
    kind = kind || Canonical.infer_kind(record)
    body = Map.delete(record, "signature")
    message = Canonical.canonicalize(body, kind)
    signature = :crypto.sign(:eddsa, :none, message, [secret, :ed25519])

    body
    |> Map.put("id", Canonical.identify(body, kind))
    |> Map.put("signature", Base.encode16(signature, case: :lower))
  end

  @doc "True iff the record's signature verifies against its own key field."
  def verify_record(record, kind \\ nil) do
    kind = kind || Canonical.infer_kind(record)
    sig_hex = Map.get(record, "signature")
    key_hex = signer_key_hex(record, kind)

    with true <- is_binary(sig_hex) and sig_hex != "",
         true <- is_binary(key_hex) and key_hex != "",
         {:ok, public} <- Base.decode16(key_hex, case: :lower),
         {:ok, signature} <- Base.decode16(sig_hex, case: :lower),
         true <- byte_size(public) == 32 and byte_size(signature) == 64 do
      body = Map.delete(record, "signature")
      message = Canonical.canonicalize(body, kind)
      :crypto.verify(:eddsa, :none, message, signature, [public, :ed25519])
    else
      _ -> false
    end
  end

  # A succession is signed by the predecessor key; everything else by source.
  defp signer_key_hex(record, kind) do
    field = if kind == "succession", do: "predecessor", else: "source"
    value = Map.get(record, field, "")

    case value do
      "ed25519:" <> hex -> hex
      _ -> nil
    end
  end
end
