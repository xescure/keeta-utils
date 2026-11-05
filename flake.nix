{
  description = "@xescure/keeta-utils, how a Keeta program gets its keys";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = function: nixpkgs.lib.genAttrs systems function;
      pkgsBySystem = forAllSystems (system: nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (system: {
        default = pkgsBySystem.${system}.callPackage ./nix/package.nix { };
      });

      # The Makefile's check, on the package's sources and installed tree,
      # offline in the sandbox.
      checks = forAllSystems (system: {
        check = self.packages.${system}.default.overrideAttrs {
          pname = "keeta-utils-check";
          buildPhase = ''
            runHook preBuild
            make -j"$NIX_BUILD_CORES" check
            runHook postBuild
          '';
          installPhase = ''
            touch $out
          '';
        };
      });

      devShells = forAllSystems (system:
        let
          pkgs = pkgsBySystem.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.nodejs_24
              pkgs.gnumake
              pkgs.jq
              pkgs.actionlint
            ];
          };
        });
    };
}
