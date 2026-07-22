{
  description = "Doorman - a macOS user authentication & account-management framework";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/24.11";
  };

  outputs = { self, nixpkgs }:
    let
      version = "0.1.0";

      systems = [ "aarch64-darwin" "x86_64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = forAllSystems (system: import nixpkgs { inherit system; });

      # Frameworks/libs every Doorman translation unit needs.
      linkFlags = "-framework Foundation -framework OpenDirectory -framework Security -lpam";

      # Universal (Apple Silicon + Intel) so released binaries run everywhere.
      archs = "-arch arm64 -arch x86_64";

      # We drive the *system* toolchain (xcrun/clang + the real macOS SDK)
      # because Doorman links private-ish frameworks (OpenDirectory) and the
      # system OpenPAM; hence __noChroot. This is the same impure-but-simple
      # approach the Makefile uses, wrapped as reproducible flake outputs.
      commonEnv = ''
        unset SDKROOT DEVELOPER_DIR NIX_APPLE_SDK_VERSION
        export PATH=/usr/bin:/bin:/usr/sbin
      '';

      # The library: static archive (for embedding) + dylib (for dynamic
      # consumers) + installed public header.
      mkDoorman = pkgs: pkgs.stdenvNoCC.mkDerivation {
        pname = "libdoorman";
        inherit version;
        src = ./doorman;
        __noChroot = true;
        dontFixup = true;
        buildPhase = ''
          ${commonEnv}
          for f in src/*.m; do
            xcrun clang ${archs} -O2 -c -Iinclude "$f" -o "$(basename "$f" .m).o"
          done
          xcrun libtool -static -o libdoorman.a *.o
          xcrun clang ${archs} -dynamiclib -install_name @rpath/libdoorman.dylib \
            -Iinclude *.o ${linkFlags} -o libdoorman.dylib
        '';
        installPhase = ''
          mkdir -p $out/lib $out/include
          cp libdoorman.a libdoorman.dylib $out/lib/
          cp include/doorman.h $out/include/
        '';
      };

      # The CLI (+ Linux-tool symlinks) linked against the static archive.
      mkCli = pkgs: doorman: pkgs.stdenvNoCC.mkDerivation {
        pname = "doorman-cli";
        inherit version;
        src = ./cli;
        __noChroot = true;
        dontFixup = true;
        buildPhase = ''
          ${commonEnv}
          xcrun clang ${archs} -O2 -o doorman \
            -I${doorman}/include doorman.m ${doorman}/lib/libdoorman.a \
            ${linkFlags} -lobjc
        '';
        installPhase = ''
          mkdir -p $out/bin
          cp doorman $out/bin/
          for t in useradd userdel passwd groupadd groupdel usermod; do
            ln -sf doorman $out/bin/$t
          done
        '';
      };

      # The console "display manager" example consumer.
      mkExample = pkgs: doorman: pkgs.stdenvNoCC.mkDerivation {
        pname = "doorman-example-macdm";
        inherit version;
        src = ./examples/macdm;
        __noChroot = true;
        dontFixup = true;
        buildPhase = ''
          ${commonEnv}
          xcrun clang ${archs} -O2 -o macdm \
            -I${doorman}/include macdm.c ${doorman}/lib/libdoorman.a \
            ${linkFlags} -lobjc
        '';
        installPhase = ''
          mkdir -p $out/bin
          cp macdm $out/bin/
        '';
      };

      # A single distributable tree (lib + header + bin + docs) that the release
      # workflow tars into a downloadable artifact.
      mkDist = pkgs: doorman: cli: example: pkgs.runCommand "doorman-dist-${version}" { } ''
        mkdir -p $out/lib $out/include $out/bin $out/share/doc/doorman
        cp ${doorman}/lib/* $out/lib/
        cp ${doorman}/include/* $out/include/
        cp -R ${cli}/bin/. $out/bin/
        cp ${example}/bin/* $out/bin/
        cp ${./doorman/README.md} $out/share/doc/doorman/README.md
        cp ${./docs/CLI_AND_PROVISIONING.md} $out/share/doc/doorman/CLI_AND_PROVISIONING.md
        cp ${./docs/AUTH_DIFFERENCES.md} $out/share/doc/doorman/AUTH_DIFFERENCES.md
        cp ${./docs/LINUX_AUTH.md} $out/share/doc/doorman/LINUX_AUTH.md
        echo "${version}" > $out/VERSION
      '';
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor.${system};
          doorman = mkDoorman pkgs;
          cli = mkCli pkgs doorman;
          example = mkExample pkgs doorman;
          dist = mkDist pkgs doorman cli example;
        in
        {
          default = doorman;
          doorman = doorman;
          doorman-cli = cli;
          doorman-example = example;
          dist = dist;
        });

      apps = forAllSystems (system: {
        # `nix run` launches the Doorman CLI.
        default = {
          type = "app";
          program = "${self.packages.${system}.doorman-cli}/bin/doorman";
        };
      });
    };
}
