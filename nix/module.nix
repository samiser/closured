self: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.closured;
in {
  options.services.closured = {
    enable = lib.mkEnableOption "an eBPF LSM exec auditor for NixOS closures";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "closured.packages.\${system}.default";
      description = "The closured package to run.";
    };

    extraFlags = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      example = ["--all" "--format" "text"];
      description = "Extra command-line flags passed to closured.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.versionAtLeast config.boot.kernelPackages.kernel.version "6.12";
        message = "closured requires kernel >= 6.12 (bpf_path_d_path kfunc)";
      }
    ];

    systemd.services.closured = {
      description = "eBPF LSM exec auditor";
      wantedBy = ["multi-user.target"];

      serviceConfig = {
        ExecStart = "${lib.getExe' cfg.package "closured"} ${lib.escapeShellArgs cfg.extraFlags}";
        Restart = "on-failure";
        RestartSec = 5;

        # Run with least privilege
        DynamicUser = true;
        AmbientCapabilities = ["CAP_BPF" "CAP_PERFMON" "CAP_MAC_ADMIN"];
        CapabilityBoundingSet = ["CAP_BPF" "CAP_PERFMON" "CAP_MAC_ADMIN"];
        LimitMEMLOCK = "infinity";

        # Hardening
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
