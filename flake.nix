{
  description = "Eva's hands: file and process operations, in-process or over an encrypted channel";

  inputs.eva.url = "git+ssh://git@github.com/nerodono/eva.git";

  outputs = { self, eva, ... }:
    eva.lib.mkServiceFlake {
      inherit self;
      pname = "eva-hands";
      description = "Eva's hands daemon: encrypted file and process operations";

      # Non-secret defaults, rendered into the world-readable store. The
      # pre-shared key is NOT here — put it in environmentFiles as
      # EVA_HANDS__KEY=... (or a secret --config file via extraConfigFiles).
      settingsDefaults = {
        hands.listen = "0.0.0.0:2222";
      };
    };
}
