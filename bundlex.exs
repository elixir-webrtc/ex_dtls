defmodule DTLS do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp natives() do
    [
      native: [
        sources: ["native.c"],
        deps: [unifex: :unifex],
        pkg_configs: ["openssl"],
        libs: ["pthread"],
        interface: :cnode,
        preprocessor: Unifex
      ]
    ]
  end
end
