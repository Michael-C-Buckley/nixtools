{pkgs ? import <nixpkgs> {}}:
pkgs.mkShell {
  buildInputs = with pkgs; [
    # Python
    python313
    python313Packages.pip
    uv
    gcc
    pkg-config
    # Pre-commit
    ruff
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
  };

  shellHook = ''
    # Set locale to avoid Python locale warnings
    export LOCALE_ARCHIVE="${pkgs.glibcLocales}/lib/locale/locale-archive"
    export LC_ALL="C.UTF-8"
  '';
}