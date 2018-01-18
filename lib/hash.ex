defmodule Ed25519.Hash do
  @moduledoc false
  defmacro __using__(_) do
    {mod, fun, pre_args, post_args} =
      Application.get_env(:ed25519, :hash_fn, {:crypto, :hash, [:sha512], []})

    quote do
      defp hash(unquote(Macro.var(:m, __MODULE__))) do
        unquote(mod).unquote(fun)(
          unquote_splicing(pre_args),
          unquote(Macro.var(:m, __MODULE__)),
          unquote_splicing(post_args)
        )
      end
    end
  end
end
