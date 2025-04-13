{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = { self, nixpkgs, crane, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        buildInputs = with pkgs; [
          autoconf
          automake
          cmake
          gcc
          gperf
          libtool
          musl
          wget
        ];
        craneLib = (crane.mkLib pkgs).overrideToolchain
          (p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml);
        ya-runtime-vm = craneLib.buildPackage {
          src = craneLib.cleanCargoSource ./.;
          inherit buildInputs;
        };
      in {
        packages.default = ya-runtime-vm;
        devShells.default = craneLib.devShell { inherit buildInputs; };
      });
}
