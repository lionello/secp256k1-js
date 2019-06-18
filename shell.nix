with import <nixpkgs> {};
mkShell {
  buildInputs = [
    nodejs-8_x
  ];
  shellHook = ''
    export PATH="$(pwd)/node_modules/.bin:$PATH"
  '';
}
