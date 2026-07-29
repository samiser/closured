{
  self,
  pkgs,
}:
let
  base = { config, ... }: {
    imports = [ self.nixosModules.default ];

    boot.kernelPackages = pkgs.linuxPackages_latest;
    boot.kernelParams = [ "lsm=landlock,lockdown,yama,integrity,apparmor,bpf" ];

    environment.systemPackages = [
      config.services.closured.package
      pkgs.jq
    ];

    system.switch.enable = true;

    services.closured = {
      enable = true;
      extraFlags = [
        "--format"
        "json"
        "--enforce"
        "--policy"
        "outside=audit"
        "--preload-ttl"
        "2"
      ];
    };
  };

  ready = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("closured.service")
    machine.wait_until_succeeds("test -S /run/closured/control")
  '';
in
{
  vm = pkgs.testers.runNixOSTest {
    name = "closured";

    nodes.machine = {
      imports = [ base ];
      virtualisation.additionalPaths = [ pkgs.hello ];
    };

    testScript = ''
      ${ready}

      with subtest("the bpf lsm is active"):
          machine.succeed("grep -w bpf /sys/kernel/security/lsm")

      with subtest("a store path outside the closure is denied"):
          machine.fail("${pkgs.hello}/bin/hello")

      with subtest("the denial is reported as an ecs event"):
          machine.wait_until_succeeds(
              "journalctl -u closured -o cat | grep '^{' | "
              "jq -e -s 'map(select(.process.executable == \"${pkgs.hello}/bin/hello\" "
              "and .closured.action == \"deny\" and .event.outcome == \"failure\")) | length > 0'"
          )

      with subtest("the socket is not reachable by non-root"):
          machine.fail("runuser -u nobody -- closured preload ${pkgs.hello}")

      with subtest("a reachable socket still rejects non-root by peer credentials"):
          machine.succeed("chmod 755 /run/closured && chmod 666 /run/closured/control")
          out = machine.fail("runuser -u nobody -- closured preload ${pkgs.hello} 2>&1")
          assert "refused the preload: permission denied" in out, out
          machine.succeed("chmod 700 /run/closured && chmod 600 /run/closured/control")

      with subtest("preload is refused for a path outside the store"):
          out = machine.fail("closured preload /tmp 2>&1")
          assert "not a store path" in out, out

      with subtest("preload allows the closure by the time it returns"):
          machine.succeed("closured preload ${pkgs.hello}")
          machine.succeed("${pkgs.hello}/bin/hello")

      with subtest("a preload that is never activated expires"):
          machine.wait_until_fails("${pkgs.hello}/bin/hello", timeout=30)
    '';
  };

  switch = pkgs.testers.runNixOSTest {
    name = "closured-switch";

    nodes = {
      machine = { nodes, ... }: {
        imports = [ base ];
        virtualisation.additionalPaths = [ nodes.next.system.build.toplevel ];
      };

      next = {
        imports = [ base ];
        environment.systemPackages = [ pkgs.hello ];
      };
    };

    testScript =
      { nodes, ... }:
      let
        next = nodes.next.system.build.toplevel;
      in
      ''
        ${ready}

        with subtest("the incoming generation is denied before it is preloaded"):
            machine.fail("${pkgs.hello}/bin/hello")

        with subtest("preload accepts the incoming system"):
            machine.succeed("closured preload ${next}")

        with subtest("activation succeeds under enforcement"):
            machine.succeed("nix-env -p /nix/var/nix/profiles/system --set ${next}")
            machine.succeed("${next}/bin/switch-to-configuration test")

        with subtest("the new generation is live and closured survived it"):
            machine.succeed('test "$(readlink -f /run/current-system)" = "${next}"')
            machine.succeed("systemctl is-active closured.service")

        with subtest("the preload is consumed once the closure covers it"):
            machine.wait_until_succeeds(
                "journalctl -u closured -o cat | grep -F 'preload ${next} activated'"
            )
            machine.succeed("${pkgs.hello}/bin/hello")
      '';
  };
}
