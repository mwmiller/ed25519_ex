defmodule Ed25519 do
  use Bitwise
  @moduledoc """
  Ed25519 signature functions

  This is mostly suitable as part of a pure Elixir solution.
  """
  @typedoc """
  public or secret key
  """
  @type key :: binary

  @typedoc """
  computed signature
  """
  @type signature :: binary

  @b 256
  @p 57896044618658097711785492504343953926634992332820282019728792003956564819949
  @l 7237005577332262213973186563042994240857116359379907606001950938285454250989
  @d -4513249062541557337682894930092624173785641285191125241628941591882900924598840740
  @i 19681161376707505956807079304988542015446066515923890162744021073123829784752
  @t254 28948022309329048855892746252171976963317496166410141009864396001978282409984
  @base {15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960 }

  defp xrecover(y) do
    xx = (y*y-1) * inv(@d*y*y+1)
    x = expmod(xx,div(@p+3,8),@p)
    if (x*x - xx) |> mod(@p) != 0, do: x = (x*@i) |> mod(@p)
    if x |> mod(2) != 0, do: @p-x, else: x
  end

  defp mod(x,_y) when x == 0, do: 0
  defp mod(x,y) when x > 0, do: rem(x,y)
  defp mod(x,y) when x < 0, do: (y + rem(x,y)) |> rem(y)

  defp hash(m), do: :crypto.hash(:sha512,m)
  defp hashint(m), do: m |> hash |> decodeint

  defp square(x), do: x * x

  defp expmod(_b,0,_m), do: 1
  defp expmod(b,e,m) do
       t = b |> expmod(div(e,2), m) |> square |> mod(m)
       if (e &&& 1) == 1, do: (t * b) |> mod(m), else: t
  end

  defp inv(x), do: x |> expmod(@p - 2, @p)

  defp edwards({x1,y1}, {x2,y2}) do
   x = (x1*y2+x2*y1) * inv(1+@d*x1*x2*y1*y2)
   y = (y1*y2+x1*x2) * inv(1-@d*x1*x2*y1*y2)
   {mod(x,@p), mod(y,@p)}
  end

  defp encodeint(x), do: x |> :binary.encode_unsigned(:little)
  defp encodepoint({x,y}) do
      y |> band(0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        |> bor((x &&& 1) <<< 255)
        |> encodeint
  end

  defp decodeint(x), do: x |> :binary.decode_unsigned(:little)
  defp decodepoint(n) do
    decoded = n |> :binary.decode_unsigned(:little)
    xc = decoded |> bsr(255)
    y  = decoded |> band(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
    x  = xrecover(y)
    point = (if (x &&& 1) == xc, do: {x,y}, else: {@p - x, y})
    if isoncurve(point), do: point, else: raise("Point off curve")
  end

  defp isoncurve({x,y}), do: (-x*x + y*y - 1 - @d*x*x*y*y) |> mod(@p) == 0

  defp rightsize(n,s) when byte_size(n) == s, do: n
  defp rightsize(n,s) when byte_size(n) <  s, do: rightsize(n<><<0>>, s)

  @doc """
  Sign a message

  If only the secret key is provided, the public key will be derived therefrom.
  This adds significant overhead.
  """
  @spec signature(binary, key, key) :: signature
  def signature(m,sk,pk \\ nil)
  def signature(m,sk,nil), do: signature(m,sk,derive_public_key(sk))
  def signature(m,sk,pk) do
    h = hash(sk)
    a = a_from_hash(h)
    r = hashint(:binary.part(h,32,32)<>m)
    bigr = r |> scalarmult(@base) |> encodepoint
    s = (r+ hashint(bigr<>pk<>m) * a) |> mod(@l)
    bigr<>encodeint(s) |> rightsize(64)
  end

  defp a_from_hash(h) do
    @t254 + (h |> :binary.part(0,32) |> :binary.decode_unsigned(:little) |> band(0xf3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8))
  end

  defp scalarmult(0, _pair), do: {0,1}
  defp scalarmult(e, p) do
     q = e |> div(2) |> scalarmult(p)
     q = edwards(q,q)
     if (e &&& 1) == 1, do: edwards(q,p), else: q
  end

  @doc """
  validate a signed message
  """
  @spec valid_signature?(signature, binary, key) :: boolean
  def valid_signature?(s,m,pk) when byte_size(s) == 64 and byte_size(pk) == 32  do
    <<for_r::binary-size(32), for_s::binary-size(32)>> = s
    r = decodepoint(for_r)
    a = decodepoint(pk)
    s = decodeint(for_s)
    h = hashint(encodepoint(r)<>pk<>m)
    scalarmult(s,@base) == edwards(r,scalarmult(h,a))
  end
  def valid_signature?(_s,_m_,_pk), do: false

  @doc """
  Generate a secret/public key pair

  Returned tuple contains `{random_secret_key, derived_public_key}`
  """
  @spec generate_key_pair :: {key,key}
  def generate_key_pair do
    secret = :crypto.strong_rand_bytes(32)
    {secret, derive_public_key(secret)}
  end

  @doc """
  derive the public signing key from the secret key
  """
  @spec derive_public_key(key) :: key
  def derive_public_key(sk) do
    sk |> hash
       |> a_from_hash
       |> scalarmult(@base)
       |> encodepoint
  end

end
