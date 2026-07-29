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
      # services.eva-hands: демон, слушающий свой порт. Ssh-демон машины ни
      # при чём — руки аутентифицируют сами, по ключам из authorized_keys.
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.eva-hands;
          format = pkgs.formats.toml { };
          keysFile =
            if cfg.authorizedKeysFile != null then
              cfg.authorizedKeysFile
            else
              pkgs.writeText "eva-hands.authorized_keys"
                (lib.concatMapStrings (key: "${key}\n") cfg.authorizedKeys);
          configFile = format.generate "eva-hands.toml" (cfg.settings // {
            inherit (cfg) listen;
            host_key = cfg.hostKeyFile;
            authorized_keys = keysFile;
          });
          port = lib.toInt (lib.last (lib.splitString ":" cfg.listen));
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

            listen = lib.mkOption {
              type = lib.types.str;
              default = "0.0.0.0:2222";
              description = ''
                Адрес и порт демона. Внутрь пускает только ключ, поэтому
                открытый порт сам по себе прав не даёт — но и лишним быть
                не должен.
              '';
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Открыть порт в firewall NixOS.";
            };

            authorizedKeys = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              example = [ "ssh-ed25519 AAAA... eva-kernel" ];
              description = ''
                Публичные ключи, которым руки открываются. Уезжают в
                общедоступный nix-store — это нормально, они публичные.
                Приватный ключ живёт у ядра.
              '';
            };

            authorizedKeysFile = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "/run/secrets/eva-hands-authorized-keys";
              description = ''
                Готовый файл ключей вместо списка — если он приезжает из
                sops. Задан — список игнорируется.
              '';
            };

            hostKeyFile = lib.mkOption {
              type = lib.types.str;
              default = "/var/lib/eva-hands/host_key";
              description = ''
                Ключ, которым машина представляется клиенту. Файла нет —
                демон заведёт его при первом запуске; его публичную половину
                (`eva-hands host-key`) клиент пинует у себя.
              '';
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
                max_write, max_hits, max_output, exec, exec_timeout_secs,
                exec_max_timeout_secs, roots. Пустой roots — вся файловая
                система. listen, host_key и authorized_keys задаются
                своими опциями и подставляются сюда сами.
              '';
            };

            user = lib.mkOption {
              type = lib.types.str;
              default = "root";
              description = ''
                Под кем работает демон. По умолчанию root: руки должны
                доставать до тех же файлов, до которых доставал shell.
                Сужают их settings.roots и settings.exec, а не отдельный
                пользователь — ключ и так даёт ровно то, что даёт.
              '';
            };

            group = lib.mkOption {
              type = lib.types.str;
              default = "root";
              description = "Группа демона.";
            };
          };

          config = lib.mkIf cfg.enable {
            assertions = [{
              assertion = cfg.authorizedKeys != [ ] || cfg.authorizedKeysFile != null;
              message = ''
                services.eva-hands: без ключей демон не пустит никого и не
                поднимется. Задай authorizedKeys или authorizedKeysFile.
              '';
            }];

            # руками пользуется ядро, а посмотреть отпечаток ключа машины
            # хозяину нужно с самой машины
            environment.systemPackages = [ cfg.package ];
            environment.etc."eva-hands.toml".source = configFile;

            networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ port ];

            systemd.services.eva-hands = {
              description = "Руки Евы";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];
              # exec нужен системный профиль: дефолтный PATH юнита — голые
              # coreutils, в нём нет ни git, ни компиляторов
              path = [ "/run/current-system/sw" ];
              environment.RUST_LOG = lib.mkDefault "info";
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/eva-hands serve --config ${configFile}";
                User = cfg.user;
                Group = cfg.group;
                Restart = "on-failure";
                RestartSec = 5;
                # ключ машины заводится сам и должен пережить перезапуск
                StateDirectory = "eva-hands";
                StateDirectoryMode = "0700";
              };
            };
          };
        };
    };
}
