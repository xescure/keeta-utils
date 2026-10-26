{
  lib,
  buildNpmPackage,
  importNpmLock,
  nodejs_24,
  gnumake,
}:

let
  package = lib.importJSON ../package.json;
  packageLock = lib.importJSON ../package-lock.json;

  # Entries that come from a dependency's own npm-shrinkwrap.json carry no
  # "resolved" URL, and npm finds them in the registry by name and version. They
  # are fetched from the same registry path, checked against their integrity.
  registryURL = path: module:
    let
      name = lib.last (lib.splitString "node_modules/" path);
    in
    "https://registry.npmjs.org/${name}/-/${baseNameOf name}-${module.version}.tgz";

  # The lock already lists the tree a package's shrinkwrap pins. Flagged with
  # hasShrinkwrap, npm resolves that tree again by name in the registry, which
  # needs the network; unflagged, it installs the same tree from the lock.
  offlineModule = path: module:
    let
      resolved = if path == "" || module ? resolved then { } else { resolved = registryURL path module; };
    in
    removeAttrs module [ "hasShrinkwrap" ] // resolved;

  offlineLock = packageLock // {
    packages = lib.mapAttrs offlineModule packageLock.packages;
  };
in
buildNpmPackage {
  pname = "keeta-utils";
  inherit (package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../package.json
      ../package-lock.json
      ../Makefile
      ../tsconfig.json
      ../tsconfig.build.json
      ../vitest.config.js
      ../src
      ../README.md
      ../SPEC.md
    ];
  };

  nodejs = nodejs_24;

  npmDeps = importNpmLock {
    inherit package;
    packageLock = offlineLock;
  };
  npmConfigHook = importNpmLock.npmConfigHook;
  # Install scripts would compile the optional native addons from source; the
  # client falls back to JavaScript without them, as it does in development.
  npmRebuildFlags = [ "--ignore-scripts" ];

  nativeBuildInputs = [ gnumake ];

  # The config hook installed node_modules from the lock, which is what the
  # Makefile's stamp stands for.
  preBuild = ''
    touch node_modules/.done
  '';

  buildPhase = ''
    runHook preBuild
    make build
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r dist package.json README.md SPEC.md $out/
    rm $out/dist/.done
    runHook postInstall
  '';

  meta = {
    description = "How a Keeta program gets its keys";
    platforms = nodejs_24.meta.platforms;
  };
}
