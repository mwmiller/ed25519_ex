ExUnit.start()

defmodule VectorHelper do
  def from_hex(<<>>), do: ""

  def from_hex(s) do
    size = div(byte_size(s), 2)
    {n, ""} = s |> Integer.parse(16)
    zero_pad(:binary.encode_unsigned(n), size)
  end

  def zero_pad(s, size) when byte_size(s) == size, do: s
  def zero_pad(s, size) when byte_size(s) < size, do: zero_pad(<<0>> <> s, size)
end

defmodule CryptoVectors do
  def testcases do
    # Reworked from http://ed25519.cr.yp.to/python/sign.input
    # sk+pk"," pk"," m"," sig+m
    "test/sign.input.txt"
    |> File.stream!()
    |> Stream.map(fn s -> String.split(s, ":") |> Enum.take(4) |> List.to_tuple() end)
    |> Enum.to_list()
  end
end
