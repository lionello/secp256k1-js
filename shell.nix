{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [
    nodejs-14_x
  ];
  shellHook = ''
    export PATH="$(pwd)/node_modules/.bin:$PATH"
  '';
}
