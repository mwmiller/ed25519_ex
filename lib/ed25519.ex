defmodule Ed25519 do
  import Bitwise

  @moduledoc """
  Ed25519 signature functions

  This is mostly suitable as part of a pure Elixir solution.

  ## Configuration

  *No configuration is needed* in most cases. However, if needed, a custom hash
  function can be configured. As per the specification - `sha512` is the default.

  `config/config.exs`

      import Config

      # The hash function will be invoked as 'Blake2.hash2b(payload, 16)'
      config :ed25519,
        hash_fn: {Blake2, :hash2b, [], [16]}

      # The hash function will be invoked as ':crypto.hash(:sha256, payload)'
      config :ed25519,
        hash_fn: {:crypto, :hash, [:sha256], []}

  """
  @typedoc """
  public or secret key
  """
  @type key :: binary

  @typedoc """
  computed signature
  """
  @type signature :: binary

  @p 57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_949
  @l 7_237_005_577_332_262_213_973_186_563_042_994_240_857_116_359_379_907_606_001_950_938_285_454_250_989
  @d -4_513_249_062_541_557_337_682_894_930_092_624_173_785_641_285_191_125_241_628_941_591_882_900_924_598_840_740
  @i 19_681_161_376_707_505_956_807_079_304_988_542_015_446_066_515_923_890_162_744_021_073_123_829_784_752
  @t254 28_948_022_309_329_048_855_892_746_252_171_976_963_317_496_166_410_141_009_864_396_001_978_282_409_984
  @base {15_112_221_349_535_400_772_501_151_409_588_531_511_454_012_693_041_857_206_046_113_283_949_847_762_202,
         46_316_835_694_926_478_169_428_394_003_475_163_141_307_993_866_256_225_615_783_033_603_165_251_855_960}

  defp xrecover(y) do
    xx = (y * y - 1) * inv(@d * y * y + 1)
    x = expmod(xx, div(@p + 3, 8), @p)

    x =
      case (x * x - xx) |> mod(@p) do
        0 -> x
        _ -> mod(x * @i, @p)
      end

    case x |> mod(2) do
      0 -> @p - x
      _ -> x
    end
  end

  defp mod(x, _y) when x == 0, do: 0
  defp mod(x, y) when x > 0, do: rem(x, y)
  defp mod(x, y) when x < 0, do: rem(y + rem(x, y), y)

  # __using__ Macro generates the hash function at compile time, which allows the
  # hashing function to be configurable without runtime overhead
  use Ed25519.Hash
  defp hashint(m), do: m |> hash |> :binary.decode_unsigned(:little)

  # :crypto.mod_pow chokes on negative inputs, so we feed it positive values
  # only and patch up the result if necessary
  defp expmod(_b, 0, _m), do: 1

  defp expmod(b, e, m) when b > 0 do
    b |> :crypto.mod_pow(e, m) |> :binary.decode_unsigned()
  end

  defp expmod(b, e, m) do
    i = b |> abs() |> :crypto.mod_pow(e, m) |> :binary.decode_unsigned()

    cond do
      mod(e, 2) == 0 -> i
      i == 0 -> i
      true -> m - i
    end
  end

  defp inv(x), do: x |> expmod(@p - 2, @p)

  defp edwards({x1, y1}, {x2, y2}) do
    x = (x1 * y2 + x2 * y1) * inv(1 + @d * x1 * x2 * y1 * y2)
    y = (y1 * y2 + x1 * x2) * inv(1 - @d * x1 * x2 * y1 * y2)
    {mod(x, @p), mod(y, @p)}
  end

  defp encodepoint({x, y}) do
    val =
      y
      |> band(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
      |> bor((x &&& 1) <<< 255)

    <<val::little-size(256)>>
  end

  defp decodepoint(<<n::little-size(256)>>) do
    xc = n |> bsr(255)
    y = n |> band(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
    x = xrecover(y)

    point =
      case x &&& 1 do
        ^xc -> {x, y}
        _ -> {@p - x, y}
      end

    if isoncurve(point), do: point, else: raise("Point off Edwards curve")
  end

  defp decodepoint(_), do: raise("Provided value not a key")

  defp isoncurve({x, y}), do: (-x * x + y * y - 1 - @d * x * x * y * y) |> mod(@p) == 0

  @doc """
  Returns whether a given `key` lies on the ed25519 curve.
  """
  @spec on_curve?(key) :: boolean
  def on_curve?(key) do
    try do
      decodepoint(key)
      true
    rescue
      _error -> false
    end
  end

  @doc """
  Sign a message

  If only the secret key is provided, the public key will be derived therefrom.
  This adds significant overhead.
  """
  @spec signature(binary, key, key) :: signature
  def signature(m, sk, pk \\ nil)
  def signature(m, sk, nil), do: signature(m, sk, derive_public_key(sk))

  def signature(m, sk, pk) do
    h = hash(sk)
    a = a_from_hash(h)
    r = hashint(:binary.part(h, 32, 32) <> m)
    bigr = r |> scalarmult(@base) |> encodepoint
    s = mod(r + hashint(bigr <> pk <> m) * a, @l)
    bigr <> <<s::little-size(256)>>
  end

  defp a_from_hash(<<h::little-size(256), _rest::binary>>) do
    @t254 +
      (h
       |> band(0xF3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8))
  end

  defp scalarmult(0, _pair), do: {0, 1}

  defp scalarmult(e, p) do
    q = e |> div(2) |> scalarmult(p)
    q = edwards(q, q)

    case e &&& 1 do
      1 -> edwards(q, p)
      _ -> q
    end
  end

  defp clamp(c) do
    c
    |> band(~~~7)
    |> band(~~~(128 <<< (8 * 31)))
    |> bor(64 <<< (8 * 31))
  end

  @doc """
  validate a signed message
  """
  @spec valid_signature?(signature, binary, key) :: boolean
  def valid_signature?(<<for_r::binary-size(32), s::little-size(256)>>, m, pk)
      when byte_size(pk) == 32 do
    r = decodepoint(for_r)
    a = decodepoint(pk)
    h = hashint(encodepoint(r) <> pk <> m)
    scalarmult(s, @base) == edwards(r, scalarmult(h, a))
  end

  def valid_signature?(_s, _m_, _pk), do: false

  @doc """
  Generate a secret/public key pair

  Returned tuple contains `{random_secret_key, derived_public_key}`
  """
  @spec generate_key_pair :: {key, key}
  def generate_key_pair do
    secret = :crypto.strong_rand_bytes(32)
    {secret, derive_public_key(secret)}
  end

  @doc """
  Generate a secret/public key pair from supplied secret

  Returned tuple contains `{secret_key, derived_public_key}`
  """
  @spec generate_key_pair(key) :: {key, key}
  def generate_key_pair(secret) do
    {secret, derive_public_key(secret)}
  end

  @doc """
  derive the public signing key from the secret key
  """
  @spec derive_public_key(key) :: key
  def derive_public_key(sk) do
    sk
    |> hash
    |> a_from_hash
    |> scalarmult(@base)
    |> encodepoint
  end

  @doc """
  Derive the x25519/curve25519 encryption key from the ed25519 signing key


  By converting an `EdwardsPoint` on the Edwards model to the corresponding `MontgomeryPoint` on the Montgomery model

  Handles either `:secret` or `:public` keys as indicated in the call

  May `raise` on an invalid input key or unknown atom

  See: https://blog.filippo.io/using-ed25519-keys-for-encryption
  """
  @spec to_curve25519(key, atom) :: key
  def to_curve25519(key, which)

  def to_curve25519(ed_public_key, :public) do
    {_, y} = decodepoint(ed_public_key)
    u = mod((1 + y) * inv(1 - y), @p)
    <<u::little-size(256)>>
  end

  def to_curve25519(ed_secret_key, :secret) do
    <<digest32::little-size(256), _::binary-size(32)>> = :crypto.hash(:sha512, ed_secret_key)
    <<clamp(digest32)::little-size(256)>>
  end
end
