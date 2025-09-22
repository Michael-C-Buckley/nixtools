{
  description = "Nix Tools Flake";

  outputs = {flake-parts, ...} @ inputs:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];

      perSystem = {pkgs, ...}: {
        # NixOS specific DevShell that fixes pathing issues
        devShells.default = import ./nix/devshells.nix {inherit pkgs;};
      };
    };

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };
}
