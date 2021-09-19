{ pkgs ? import <nixpkgs> {} }:
let
  customBuildRustCrateForPkgs = pkgs: pkgs.buildRustCrate.override {
    defaultCrateOverrides = pkgs.defaultCrateOverrides // {
      "authn" = attrs: {
        buildInputs =
          if pkgs.stdenv.isDarwin
          then [ pkgs.darwin.apple_sdk.frameworks.Security ]
          else [];
        # copy the sql migrations
        postInstall = ''
          cp -rP sql $out/sql
        '';
      };
    };
  };
  generatedBuild = import ./Cargo.nix {
    inherit pkgs;
    buildRustCrateForPkgs = customBuildRustCrateForPkgs;
    rootFeatures = [ "server" "cli" ];
  };
in
  generatedBuild.rootCrate.build

