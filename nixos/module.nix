{
  config,
  defaultPackage,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.ironet;
in
{
  options.services.ironet = {
    enable = lib.mkEnableOption "the Ironet data-plane daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "inputs.ironet.packages.${pkgs.stdenv.hostPlatform.system}.default";
      description = "ironet package containing the CLI and daemon.";
    };
    configFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/ironet/config.toml";
      description = "Sealed ironet configuration file.";
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/ironet/control.sock";
      description = "Unix control socket path.";
    };

  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # MagicDNS is registered as per-link split DNS over resolve1. Keep the
    # resolver and polkit broker available, and grant only the methods used by
    # the capability-bounded ironet service account.
    services.resolved.enable = true;
    security.polkit.enable = true;
    security.polkit.extraConfig = builtins.readFile ../systemd/90-ironet-resolved.rules;

    users.groups.ironet = { };
    users.users.ironet = {
      isSystemUser = true;
      group = "ironet";
      home = "/var/lib/ironet";
      description = "Ironet daemon";
    };

    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv4.conf.all.rp_filter" = 2;
      "net.ipv4.conf.default.rp_filter" = 2;
      "net.ipv6.conf.all.forwarding" = 1;
    };

    systemd.services.ironet = {
      description = "Ironet Protocol V2 data plane";
      wantedBy = [ "multi-user.target" ];
      wants = [
        "network-online.target"
        "systemd-resolved.service"
      ];
      after = [
        "network-online.target"
        "dbus.service"
        "systemd-resolved.service"
      ];
      path = [
        pkgs.iproute2
        pkgs.iptables
      ];
      environment = {
        RUST_LOG = "info";
        IRONET_LOG_FORMAT = "json";
      };
      preStart = ''
        ${lib.getExe' cfg.package "ironet"} doctor --config ${lib.escapeShellArg (toString cfg.configFile)}
      '';
      serviceConfig = {
        Type = "simple";
        User = "ironet";
        Group = "ironet";
        ExecStart = "${cfg.package}/bin/ironetd --config ${cfg.configFile} --socket ${cfg.socketPath}";
        ExecReload = "${lib.getExe' cfg.package "ironet"} reload --socket ${cfg.socketPath}";
        Restart = "on-failure";
        RestartSec = "2s";
        TimeoutStopSec = "20s";
        UMask = "0077";
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        LockPersonality = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
        ReadWritePaths = [
          "/run/ironet"
          "/var/lib/ironet"
        ];
        StateDirectory = "ironet";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "ironet";
        RuntimeDirectoryMode = "0770";
      };
    };
  };
}
