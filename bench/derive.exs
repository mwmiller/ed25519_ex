{sk, pk} = Ed25519.generate_key_pair()
sig = Ed25519.signature("benchmark message", sk, pk)

Benchee.run(
  %{
    "derive_public_key/1" => fn -> Ed25519.derive_public_key(sk) end,
    "signature/3" => fn -> Ed25519.signature("benchmark message", sk, pk) end,
    "valid_signature?/3" => fn -> Ed25519.valid_signature?(sig, "benchmark message", pk) end
  },
  warmup: 1,
  time: 5
)
