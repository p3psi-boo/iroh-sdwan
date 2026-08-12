{
  config,
  defaultPackage,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.iroh-sdwan;
in
{
  options.services.iroh-sdwan = {
    enable = lib.mkEnableOption "the iroh SD-WAN data-plane daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "inputs.iroh-sdwan.packages.${pkgs.stdenv.hostPlatform.system}.default";
      description = "iroh-sdwan package containing the CLI and daemon.";
    };
    configFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/iroh-sdwan/config.toml";
      description = "Sealed iroh-sdwan configuration file.";
    };

    socketPath = lib.mkOption {
      type = lib.types.str;
      default = "/run/iroh-sdwan/control.sock";
      description = "Unix control socket path.";
    };

  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    users.groups.iroh-sdwan = { };
    users.users.iroh-sdwan = {
      isSystemUser = true;
      group = "iroh-sdwan";
      home = "/var/lib/iroh-sdwan";
      description = "iroh SD-WAN daemon";
    };

    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv4.conf.all.rp_filter" = 2;
      "net.ipv4.conf.default.rp_filter" = 2;
      "net.ipv6.conf.all.forwarding" = 1;
    };

    systemd.services.iroh-sdwan = {
      description = "iroh SD-WAN data plane with FlowRouter";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      path = [
        pkgs.iproute2
      ];
      environment = {
        RUST_LOG = "info";
        IROH_SDWAN_LOG_FORMAT = "json";
      };
      preStart = ''
        ${lib.getExe' cfg.package "iroh-sdwan"} doctor --config ${lib.escapeShellArg (toString cfg.configFile)}
      '';
      serviceConfig = {
        Type = "simple";
        User = "iroh-sdwan";
        Group = "iroh-sdwan";
        ExecStart = "${cfg.package}/bin/iroh-sdwand --config ${cfg.configFile} --socket ${cfg.socketPath}";
        ExecReload = "${lib.getExe' cfg.package "iroh-sdwan"} reload --socket ${cfg.socketPath}";
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
          "/run/iroh-sdwan"
          "/var/lib/iroh-sdwan"
        ];
        StateDirectory = "iroh-sdwan";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "iroh-sdwan";
        RuntimeDirectoryMode = "0770";
      };
    };
  };
}
