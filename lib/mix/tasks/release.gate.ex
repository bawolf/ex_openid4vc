defmodule Mix.Tasks.Release.Gate do
  use Mix.Task

  @shortdoc "Runs the ex_openid4vc release gate checks"

  @moduledoc """
  Runs the standard release gate for `ex_openid4vc`.

  The default gate checks:

  - formatting
  - test suite
  - released parity corpus presence
  - docs build
  - Hex package build

  Pass `--include-live-oracle` to additionally require the maintainer-only live
  oracle property tests.
  """

  @required_docs ~w(
    README.md
    PARITY_MATRIX.md
    FIXTURE_POLICY.md
    SUPPORTED_FEATURES.md
    INTEROP_NOTES.md
    RELEASE_CHECKLIST.md
    CHANGELOG.md
    LICENSE
  )

  @released_manifest "test/fixtures/upstream/released/manifest.json"

  @impl Mix.Task
  def run(args) do
    {opts, _argv, invalid} = OptionParser.parse(args, strict: [include_live_oracle: :boolean])

    if invalid != [] do
      Mix.raise("unknown options: #{Enum.map_join(invalid, ", ", &elem(&1, 0))}")
    end

    ensure_release_docs!()
    ensure_released_corpus!()

    run_mix_command!(["format", "--check-formatted"])
    run_mix_command!(["test"], %{"MIX_ENV" => "test"})

    if opts[:include_live_oracle] do
      ensure_live_oracle_enabled!()
      run_mix_command!(["test", "test/upstream_live_property_test.exs"], %{"MIX_ENV" => "test"})
    end

    run_mix_command!(["docs"])
    run_mix_command!(["hex.build"], %{"EX_OPENID4VC_USE_LOCAL_DEPS" => "0"})

    Mix.shell().info("ex_openid4vc release gate passed")
  end

  defp ensure_release_docs! do
    missing =
      Enum.reject(@required_docs, fn path ->
        File.regular?(path)
      end)

    if missing != [] do
      Mix.raise("missing release docs: #{Enum.join(missing, ", ")}")
    end
  end

  defp ensure_released_corpus! do
    unless File.regular?(@released_manifest) do
      Mix.raise("missing released parity manifest: #{@released_manifest}")
    end
  end

  defp ensure_live_oracle_enabled! do
    unless System.get_env("EX_OPENID4VC_LIVE_ORACLE") == "1" do
      Mix.raise("set EX_OPENID4VC_LIVE_ORACLE=1 before using --include-live-oracle")
    end

    oracle_root = Path.expand("scripts/upstream_parity")
    node_modules = Path.join(oracle_root, "node_modules")
    oracle_script = Path.join(oracle_root, "oracle.js")

    unless File.regular?(oracle_script) and File.dir?(node_modules) do
      Mix.raise("install scripts/upstream_parity dependencies before using --include-live-oracle")
    end
  end

  defp run_mix_command!(args, extra_env \\ %{}) do
    env =
      %{}
      |> maybe_put_env("EX_OPENID4VC_USE_LOCAL_DEPS")
      |> maybe_put_env("EX_OPENID4VC_LIVE_ORACLE")
      |> Map.merge(extra_env)

    case System.cmd("mix", args,
           into: IO.stream(:stdio, :line),
           stderr_to_stdout: true,
           env: Enum.to_list(env)
         ) do
      {_output, 0} ->
        :ok

      {_output, status} ->
        Mix.raise("mix #{Enum.join(args, " ")} failed with exit status #{status}")
    end
  end

  defp maybe_put_env(env, key) do
    case System.get_env(key) do
      nil -> env
      value -> Map.put(env, key, value)
    end
  end
end
