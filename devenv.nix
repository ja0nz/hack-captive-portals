{ pkgs, ... }:

{
  # https://devenv.sh/packages/
  packages = with pkgs; [ babashka iw nmap sipcalc ];

  # https://devenv.sh/scripts/
  scripts.run.exec = "sudo ./hack-captive-portal.sh";
  scripts.run_bb.exec = "sudo ./hack-captive-portal.bb";
}
