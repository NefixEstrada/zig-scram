{ pkgs ? import <nixpkgs> {}, zig }:
  pkgs.mkShell {
    nativeBuildInputs = with pkgs; [
      zig
    ];
}
