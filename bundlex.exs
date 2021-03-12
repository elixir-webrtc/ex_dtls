defmodule ExDTLS.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp natives() do
    [
      native: [
        sources: ["native.c", "dtls.c", "dyn_buff.c"],
        deps: [unifex: :unifex],
        pkg_configs: ["openssl"],
        compiler_flags: ["-DCNODE_DEBUG"],
        libs: ["pthread"],
        interface: :cnode,
        preprocessor: Unifex
      ]
    ]
  end
end
