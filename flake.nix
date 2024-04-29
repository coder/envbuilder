{
  description = "Build development environments from a Dockerfile on Docker, Kubernetes, and OpenShift. Enable developers to modify their development environment quickly.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
        devShellPackages = with pkgs; [
          go_1_21
        ];
      in
      {
        devShell = pkgs.mkShell {
          name = "devShell";
          buildInputs = devShellPackages;
        };
      }
    );
}
