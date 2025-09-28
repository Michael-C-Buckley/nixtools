{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    # Python
    python313
    uv
    gcc
    pkg-config

    # Pre-commit
    ruff
    pyrefly
    lefthook
    typos
    treefmt
    bandit
  ];
  env = {
    LD_LIBRARY_PATH = with pkgs;
      lib.makeLibraryPath [
        stdenv.cc.cc
      ];
    UV_LINK_MODE="copy";
    LOCALE_ARCHIVE="${pkgs.glibcLocales}/lib/locale/locale-archive";
    LC_ALL="C.UTF-8";
  };

  shellHook = ''
    lefthook install
    uv sync --all-groups
  '';
}
