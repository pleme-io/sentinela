{
  description = "sentinela — the Darwin GitOps node-sync daemon (the Mac peer of NixOS comin)";

  # Canonical pleme-io Rust-tool consumer flake. substrate.rust.tool pre-binds
  # nixpkgs / crate2nix / flake-utils / fenix / devenv / gen — every dependency the
  # build kit needs — so a substrate bump propagates fleet-wide without touching this
  # file. toolName (sentinela) + repo are read from the typed
  # `flake_metadata.sentinela` in Cargo.build-spec.json.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { substrate, ... }: substrate.rust.tool {
    src = ./.;
    member = "sentinela"; # the deployable bin; the other 2 members are libraries
    module = {
      description = "sentinela — the Darwin GitOps node-sync daemon (Mac peer of comin)";
    };
  };
}
