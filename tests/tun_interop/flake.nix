# Nix flake for TUN interop testing.
#
# Usage (from repo root):
#   nix run ./tests/tun_interop#tun-test
#
# Or build the Docker image:
#   nix build ./tests/tun_interop#docker-image
#   docker load < result
#   docker run --cap-add=NET_ADMIN --device=/dev/net/tun tinytcp-tun-test
#
# NixOS VM test (fully hermetic, no Docker needed):
#   nix build ./tests/tun_interop#checks.x86_64-linux.tun-interop
{
  description = "tinytcp TUN interop tests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        packages = {
          docker-image = pkgs.dockerTools.buildImage {
            name = "tinytcp-tun-test";
            tag = "latest";
            copyToRoot = pkgs.buildEnv {
              name = "test-env";
              paths = with pkgs; [
                bash
                coreutils
                iproute2
                iputils
                netcat-gnu
              ];
            };
            config = {
              Cmd = [ "/bin/bash" "/tests/tun_interop/run_test.sh" ];
            };
          };
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            zig
            iproute2
            iputils
            netcat-gnu
          ];
        };
      }
    ) // {
      # NixOS VM test (Linux only)
      checks.x86_64-linux.tun-interop =
        let
          pkgs = nixpkgs.legacyPackages.x86_64-linux;
        in
        pkgs.nixosTest {
          name = "tinytcp-tun-interop";

          nodes.machine = { pkgs, ... }: {
            virtualisation.memorySize = 1024;
            environment.systemPackages = with pkgs; [
              iproute2
              iputils
              netcat-gnu
            ];
          };

          # TODO: integrate zig build into VM image
          testScript = ''
            machine.wait_for_unit("multi-user.target")
            machine.succeed("echo 'NixOS VM test placeholder - build integration TBD'")
          '';
        };
    };
}
