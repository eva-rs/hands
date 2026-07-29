{
  description = "eva-hands — руки Евы на рабочей машине";

  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = inputs@{ self, flake-utils, fenix, nixpkgs, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ fenix.overlays.default ];
        pkgs = import nixpkgs { inherit system overlays; };
        rust = pkgs.fenix.stable.withComponents [
          "cargo"
          "rustc"
          "rust-src"
          "rust-analyzer"
          "clippy"
          "rustfmt"
        ];

      in
      {
        packages = rec {
          eva-hands = pkgs.rustPlatform.buildRustPackage {
            pname = "eva-hands";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
          };
          default = eva-hands;
        };

        devShells.default = pkgs.mkShell {
          packages = [ rust ];
          buildInputs = with pkgs; [ stdenv.cc.cc.lib ];
        };
      }
    ) // {
      # services.eva-hands: пакет в системный профиль (ssh-сессия зовёт
      # `eva-hands serve` голым именем) плюс /etc/eva-hands.toml с потолками.
      # Резидентный юнит поднимается только под `socket` — по ssh демон
      # живёт ровно столько, сколько живёт соединение.
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.eva-hands;
          format = pkgs.formats.toml { };
          configFile = format.generate "eva-hands.toml" cfg.settings;
        in
        {
          options.services.eva-hands = {
            enable = lib.mkEnableOption "руки Евы на этой машине";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.eva-hands;
              defaultText = lib.literalExpression "eva-hands.packages.<system>.default";
              description = "Пакет демона.";
            };

            settings = lib.mkOption {
              type = format.type;
              default = { };
              example = lib.literalExpression ''
                {
                  max_read = 67108864;
                  exec = true;
                  roots = [ "/srv/games" "/home/nero/dev" ];
                }
              '';
              description = ''
                Потолки машины, они же /etc/eva-hands.toml: max_read,
                max_write, max_hits, max_output, exec,
                exec_timeout_secs, exec_max_timeout_secs, roots.
                Пустой roots — вся файловая система.
              '';
            };

            socket = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "/run/eva-hands/sock";
              description = ''
                Поднять резидентный демон на юникс-сокете по этому пути.
                Нужен только клиенту на этой же машине; путь через ssh
                демона не требует — там его запускает сама сессия.
              '';
            };

            user = lib.mkOption {
              type = lib.types.str;
              default = "root";
              description = ''
                Под кем работает резидентный демон. К ssh-пути отношения
                не имеет: там демон работает под тем, кто вошёл по ключу.
              '';
            };

            group = lib.mkOption {
              type = lib.types.str;
              default = "root";
              description = "Группа резидентного демона; она же владеет сокетом.";
            };

            socketMode = lib.mkOption {
              type = lib.types.str;
              default = "0600";
              description = "Права на сокете, восьмеричные.";
            };
          };

          config = lib.mkIf cfg.enable {
            # ssh запускает `eva-hands serve` голым именем: без системного
            # профиля неинтерактивная сессия его не найдёт
            environment.systemPackages = [ cfg.package ];
            environment.etc."eva-hands.toml".source = configFile;

            systemd.services.eva-hands = lib.mkIf (cfg.socket != null) {
              description = "Руки Евы (юникс-сокет)";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];
              # exec нужен системный профиль: дефолтный PATH юнита — голые
              # coreutils, в нём нет ни git, ни компиляторов
              path = [ "/run/current-system/sw" ];
              environment.RUST_LOG = lib.mkDefault "info";
              serviceConfig = {
                ExecStart = lib.concatStringsSep " " [
                  "${cfg.package}/bin/eva-hands daemon"
                  "--listen ${lib.escapeShellArg cfg.socket}"
                  "--config ${configFile}"
                  "--mode ${cfg.socketMode}"
                ];
                User = cfg.user;
                Group = cfg.group;
                Restart = "on-failure";
                RestartSec = 5;
                RuntimeDirectory = "eva-hands";
                RuntimeDirectoryPreserve = true;
              };
            };
          };
        };
    };
}
