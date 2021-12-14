defmodule ExPassword.ExternalArgon2.MixProject do
  use Mix.Project

  def project do
    [
      app: :expassword_external_argon2,
      version: "0.2.0",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      test_paths: ~W[../expassword_argon2/test],
      deps: deps(),
      description: description(),
      package: package(),
      source_url: "https://github.com/julp/expassword_external_argon2",
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {ExPassword.ExternalArgon2.Application, []},
      extra_applications: ~W[logger runtime_tools]a,
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ~W[lib ../expassword_argon2/test/support]
  defp elixirc_paths(_), do: ~W[lib]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:expassword, "~> 0.2"},
      {:earmark, "~> 1.4", only: :dev},
      {:ex_doc, "~> 0.22", only: :dev},
      #{:dialyxir, "~> 1.1", only: ~W[dev test]a, runtime: false},
    ]
  end

  defp description() do
    ~S"""
    An alternate argon2 "plugin" for ExPassword (using an external command, php, instead of a NIF)
    """
  end

  defp package() do
    [
      files: ~W[lib mix.exs README*],
      licenses: ~W[BSD],
      links: %{"GitHub" => "https://github.com/julp/expassword_external_argon2"},
    ]
  end
end
