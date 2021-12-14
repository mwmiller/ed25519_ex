defmodule Ed25519Test do
  use ExUnit.Case
  import VectorHelper
  doctest Ed25519

  test "keys" do
    {sk, pk} = Ed25519.generate_key_pair()

    assert byte_size(sk) == 32, "Proper sized secret key"
    assert byte_size(pk) == 32, "Proper sized public key"

    # test key generation with provided secret using the random sk
    {sk, pk2} = Ed25519.generate_key_pair(sk)
    assert pk2 == pk

    assert Ed25519.derive_public_key(sk) == pk, "Can re-derive the public key from the secret key"
  end

  test "to_curve25519" do
    sk =
      <<244, 62, 48, 200, 177, 103, 228, 134, 216, 53, 71, 1, 105, 127, 46, 210, 56, 38, 17, 114,
        171, 83, 82, 29, 106, 115, 58, 178, 237, 213, 10, 226>>

    curve_sk =
      <<208, 75, 48, 29, 66, 212, 83, 245, 40, 51, 19, 213, 150, 216, 65, 96, 165, 206, 255, 140,
        179, 10, 215, 92, 134, 155, 30, 80, 229, 104, 104, 76>>

    pk =
      <<70, 55, 170, 144, 189, 49, 220, 167, 226, 113, 150, 15, 53, 138, 156, 39, 230, 211, 77,
        195, 100, 174, 112, 112, 204, 9, 154, 19, 165, 70, 133, 80>>

    curve_pk =
      <<70, 145, 87, 124, 161, 125, 23, 116, 180, 121, 44, 30, 41, 206, 43, 88, 241, 75, 104, 65,
        12, 215, 105, 123, 62, 226, 228, 124, 106, 111, 39, 48>>

    assert Ed25519.to_curve25519(sk, :secret) == curve_sk

    assert Ed25519.to_curve25519(pk, :public) == curve_pk

    assert_raise RuntimeError, "Point off Edwards curve", fn ->
      Ed25519.to_curve25519(curve_pk, :public)
    end

    assert_raise FunctionClauseError,
                 "no function clause matching in Ed25519.to_curve25519/2",
                 fn ->
                   Ed25519.to_curve25519(curve_pk, :private)
                 end

    assert_raise RuntimeError, "Provided value not a key", fn ->
      Ed25519.to_curve25519(<<>>, :public)
    end
  end

  @tag timeout: :infinity
  test "cr.yp.to examples" do
    test_em = fn
      [], _fun ->
        :noop

      [e | xamples], fun ->
        {<<s::binary-size(64), p::binary-size(64)>>, dp, m, <<sig::binary-size(128), dm::binary>>} =
          e

        assert p == dp, "Duplicate public key: " <> dp
        assert m == dm, "Duplicate message: " <> dm

        sk = from_hex(s)
        pk = from_hex(p)
        ms = from_hex(m)
        si = from_hex(sig)

        assert Ed25519.derive_public_key(sk) == pk, "SK: " <> s
        assert Ed25519.signature(ms, sk, pk) == si, "SIG: " <> sig
        assert Ed25519.valid_signature?(si, ms, pk), "MSG:" <> m
        fun.(xamples, fun)
    end

    test_em.(CryptoVectors.testcases(), test_em)
  end
end
