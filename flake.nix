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
            xorg.libX11
            xorg.libXcursor
            xorg.libXrandr
            xorg.libXi
          ];

          darwinBuildInputs = with pkgs; [ libiconv ];

          linuxLibraryPath = lib.makeLibraryPath (with pkgs; [
            wayland
            libxkbcommon
            vulkan-loader
            libGL
            xorg.libX11
            xorg.libXcursor
            xorg.libXrandr
            xorg.libXi
            fontconfig
            freetype
          ]);

          platformBuildInputs =
            if pkgs.stdenv.isLinux then linuxBuildInputs
            else if pkgs.stdenv.isDarwin then darwinBuildInputs
            else [ ];
        in
        {
          devShells.default = pkgs.mkShell {
            RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
            RUST_BACKTRACE = 1;
            LD_LIBRARY_PATH = if pkgs.stdenv.isLinux then linuxLibraryPath else "";
            DYLD_FALLBACK_LIBRARY_PATH =
              if pkgs.stdenv.isDarwin then "${pkgs.libiconv}/lib" else "";
            nativeBuildInputs = commonBuildInputs ++ platformBuildInputs;
            shellHook = ''
              echo "🖥️  Starlab Desktop dev shell (Iced + frost-mpc engine)"
              echo "  cargo run    - launch the desktop wallet"
            '';
          };
        };
    };
}
