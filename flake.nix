{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    { nixpkgs, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        { pkgs, system, lib, ... }:
        let
          commonBuildInputs = with pkgs; [
            pkg-config
            rustc
            cargo
            clippy
            rustfmt
            clang
            lld
            # Iced text rendering
            fontconfig
            freetype
          ];

          # Iced (wgpu/winit) graphics + windowing on Linux.
          linuxBuildInputs = with pkgs; [
            wayland
            libxkbcommon
            wayland-protocols
            libGL
            vulkan-loader
            mesa
            libx11
            libxcursor
            libxrandr
            libxi
          ];

          darwinBuildInputs = with pkgs; [ libiconv ];

          linuxLibraryPath = lib.makeLibraryPath (with pkgs; [
            wayland
            libxkbcommon
            vulkan-loader
            libGL
            libx11
            libxcursor
            libxrandr
            libxi
            fontconfig
            freetype
          ]);

          platformBuildInputs =
            if pkgs.stdenv.hostPlatform.isLinux then linuxBuildInputs
            else if pkgs.stdenv.hostPlatform.isDarwin then darwinBuildInputs
            else [ ];
        in
        {
          devShells.default = pkgs.mkShell {
            RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
            RUST_BACKTRACE = 1;
            LD_LIBRARY_PATH = if pkgs.stdenv.hostPlatform.isLinux then linuxLibraryPath else "";
            DYLD_FALLBACK_LIBRARY_PATH =
              if pkgs.stdenv.hostPlatform.isDarwin then "${pkgs.libiconv}/lib" else "";
            nativeBuildInputs = commonBuildInputs ++ platformBuildInputs;
            shellHook = ''
              echo "🖥️  Starlab Desktop dev shell (Iced + starlab-mpc engine)"
              echo "  cargo run    - launch the desktop wallet"
            '';
          };
        };
    };
}
