defmodule ExDTLS.Mixfile do
  use Mix.Project

  @version "0.18.0"
  @github_url "https://github.com/elixir-webrtc/ex_dtls"

  def project do
    [
      app: :ex_dtls,
      version: @version,
      elixir: "~> 1.12",
      compilers: [:unifex, :bundlex] ++ Mix.compilers(),
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: dialyzer(),

      # hex
      description: "DTLS and DTLS-SRTP library for Elixir, based on OpenSSL.",
      package: package(),

      # docs
      name: "ExDTLS",
      source_url: @github_url,
      homepage_url: "https://membrane.stream",
      docs: docs(),

      # code coverage
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.json": :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:unifex, "~> 1.0"},
      {:bundlex, "~> 1.5.3"},
      {:ex_doc, "~> 0.29", only: :dev, runtime: false},
      {:dialyxir, "~> 1.0", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: :dev, runtime: false},
      {:excoveralls, "~> 0.14", only: [:dev, :test], runtime: false}
    ]
  end

  defp dialyzer() do
    opts = [
      flags: [:error_handling]
    ]

    if System.get_env("CI") == "true" do
      # Store PLTs in cacheable directory for CI
      [plt_local_path: "priv/plts", plt_core_path: "priv/plts"] ++ opts
    else
      opts
    end
  end

  defp package do
    [
      maintainers: ["Membrane Team"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @github_url},
      files: ["lib", "mix.exs", "README*", "LICENSE*", ".formatter.exs", "bundlex.exs", "c_src"],
      exclude_patterns: [~r"c_src/.*/_generated.*"]
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "LICENSE"],
      formatters: ["html"],
      source_ref: "v#{@version}",
      nest_modules_by_prefix: [ExDTLS]
    ]
  end
end
