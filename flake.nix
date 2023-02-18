{
  description = "Nix pwn env";
  nixConfig.bash-prompt = "\[pwn\]; ";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
  };

  # Flake outputs
  outputs = { self, nixpkgs }:
    let
      # Systems supported
      allSystems = [
        "x86_64-linux" # 64-bit Intel/AMD Linux
        "aarch64-linux" # 64-bit ARM Linux
        "x86_64-darwin" # 64-bit Intel macOS
        "aarch64-darwin" # 64-bit ARM macOS
      ];

      # Helper to provide system-specific attributes
      nameValuePair = name: value: { inherit name value; };
      genAttrs = names: f: builtins.listToAttrs (map (n: nameValuePair n (f n)) names);
      forAllSystems = f: genAttrs allSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      # Development environment output
      devShells = forAllSystems ({ pkgs }: {
        default =
          let
            python = pkgs.python311; # Use Python 3.11
          in
          pkgs.mkShell {
            packages = [ # The Nix packages provided in the environment

              # Python plus helper tools
              (python.withPackages (ps: with ps; [
                virtualenv # Virtualenv
                pip # The pip installer
                pwntools # The pip installer
              ]))

            ];
          };
      });
    };
}
