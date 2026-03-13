defmodule ExOpenid4vc.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/bawolf/ex_openid4vc"

  def project do
    [
      app: :ex_openid4vc,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "OpenID4VCI issuer-side metadata, request, proof, deferred issuance, and notification boundaries for Elixir.",
      package: package(),
      source_url: @source_url,
      homepage_url: @source_url,
      docs: [
        main: "readme",
        extras: [
          "README.md",
          "PARITY_MATRIX.md",
          "FIXTURE_POLICY.md",
          "SUPPORTED_FEATURES.md",
          "INTEROP_NOTES.md",
          "RELEASE_CHECKLIST.md",
          "CHANGELOG.md",
          "LICENSE"
        ],
        source_ref: "v#{@version}",
        source_url: @source_url
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :public_key],
      mod: {ExOpenid4vc.Application, []}
    ]
  end

  defp deps do
    [
      ex_did_dep(),
      {:ex_doc, "~> 0.37", only: :dev, runtime: false},
      {:jason, "~> 1.4"},
      {:jose, "~> 1.11"},
      {:stream_data, "~> 1.1", only: :test}
    ]
  end

  defp ex_did_dep do
    if System.get_env("EX_OPENID4VC_USE_LOCAL_DEPS") == "1" do
      {:ex_did, path: "../ex_did"}
    else
      {:ex_did, "~> 0.1.2"}
    end
  end

  defp package do
    [
      licenses: ["MIT"],
      maintainers: ["Bryant Wolf"],
      links: %{
        "GitHub" => @source_url,
        "Hex" => "https://hex.pm/packages/ex_openid4vc",
        "Docs" => "https://hexdocs.pm/ex_openid4vc",
        "CI" => "#{@source_url}/actions/workflows/ci.yml",
        "Parity Matrix" => "#{@source_url}/blob/main/PARITY_MATRIX.md",
        "Fixture Policy" => "#{@source_url}/blob/main/FIXTURE_POLICY.md",
        "Interop Notes" => "#{@source_url}/blob/main/INTEROP_NOTES.md",
        "Supported Features" => "#{@source_url}/blob/main/SUPPORTED_FEATURES.md",
        "Release Checklist" => "#{@source_url}/blob/main/RELEASE_CHECKLIST.md",
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "License" => "#{@source_url}/blob/main/LICENSE"
      }
    ]
  end
end
