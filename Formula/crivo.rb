# Gerado por scripts/packages.py a cada release; não edite à mão.
class Crivo < Formula
  desc "CLI de acesso a Postgres governado por um arquivo de política"
  homepage "https://github.com/JonathanSantos/crivo"
  version "0.1.4"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.1.4/crivo-macos-arm64"
      sha256 "6e25a9fd4ae6c19a07e42c50c0c89e0550419d869ad46b53173bf6d32ef4a13a"
    else
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.1.4/crivo-macos-amd64"
      sha256 "2de0dc434689cda49bf42372e0258a9fa1efbe0edcaf133e2e037bbf3c8f2183"
    end
  end

  on_linux do
    depends_on arch: :x86_64

    url "https://github.com/JonathanSantos/crivo/releases/download/v0.1.4/crivo-linux-amd64"
    sha256 "06087bc89347fec7d15a991b782bdf1ceb390aa844bce50139f4603e407632f7"
  end

  def install
    bin.install Dir["crivo-*"].first => "crivo"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/crivo version")
  end
end
