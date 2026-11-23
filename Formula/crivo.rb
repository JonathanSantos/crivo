# Gerado por scripts/packages.py a cada release; não edite à mão.
class Crivo < Formula
  desc "CLI de acesso a Postgres governado por um arquivo de política"
  homepage "https://github.com/JonathanSantos/crivo"
  version "0.2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.2.0/crivo-macos-arm64"
      sha256 "07ba8d6eb2a150f047ba169c99e1b5d9e6b1310905059d214ce3ef3e57566a47"
    else
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.2.0/crivo-macos-amd64"
      sha256 "175db6aee8ff617e302cb7a7bca8f3b150ec38e65b30d2f2ebab736529401629"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.2.0/crivo-linux-arm64"
      sha256 "b85799d539fc241acd4cb62b5f6f0c5d9690348c26695d615de103872e60fc77"
    else
      url "https://github.com/JonathanSantos/crivo/releases/download/v0.2.0/crivo-linux-amd64"
      sha256 "b637e851c8bb7dc04ed47a7c769a94c9ca6b22dd63309f92a73c0b74bed81712"
    end
  end

  def install
    bin.install Dir["crivo-*"].first => "crivo"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/crivo version")
  end
end
