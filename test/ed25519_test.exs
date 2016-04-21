defmodule Ed25519Test do
  use PowerAssert
  import VectorHelper
  doctest Ed25519

  test "keys" do
    {sk,pk} = Ed25519.generate_key_pair

    assert byte_size(sk) == 32, "Proper sized secret key"
    assert byte_size(pk) == 32, "Proper sized public key"

    assert Ed25519.derive_public_key(sk) == pk, "Can re-derive the public key from the secret key"

  end

  test "cr.yp.to examples" do
    test_em = fn
              ([], _fun)              -> :noop
              ([e|xamples], fun) ->
                {<<s::binary-size(64),p::binary-size(64)>>,dp,m,<<sig::binary-size(128),dm::binary>>} = e

                assert p == dp, "Duplicate public key: "<>dp
                assert m == dm, "Duplicate message: "<>dm

                sk = from_hex(s)
                pk = from_hex(p)
                ms = from_hex(m)
                si = from_hex(sig)

                assert Ed25519.derive_public_key(sk) == pk, "SK: "<>s
                assert Ed25519.signature(ms,sk,pk) == si, "SIG: "<>sig
                assert Ed25519.valid_signature?(si,ms,pk) , "MSG:"<>m
                fun.(xamples, fun)
              end

    test_em.(CryptoVectors.testcases, test_em)
  end
end
