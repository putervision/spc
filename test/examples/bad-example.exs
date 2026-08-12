# Elixir bad example anti-patterns
defmodule BadExample do
  def recursive_factorial(0), do: 1
  def recursive_factorial(n), do: n * recursive_factorial(n - 1)

  def unbounded_loop do
    Stream.repeatedly(fn -> :ok end) |> Enum.each(fn _ -> :ok end)
  end
end
