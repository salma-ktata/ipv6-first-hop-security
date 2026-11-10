#!/usr/bin/env python3
# Deploiement de la base vulnerable (radvd/FRR/Kea) via Ansible.
# Le durcissement se fait avec harden.sh (a la racine du depot), pas ici.
import argparse, subprocess, sys
from pathlib import Path

ANSIBLE_DIR = Path(__file__).parent
PLAYBOOK = ANSIBLE_DIR / "site.yml"

PHASES = {
    "vulnerable": ["phase1"],
}

def run_tags(tags, check=False):
    cmd = ["ansible-playbook", str(PLAYBOOK), "--tags", ",".join(tags)]
    if check:
        cmd += ["--check", "--diff"]
    print(f"\n>>> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=ANSIBLE_DIR)
    if result.returncode != 0:
        print(f"\n[X] Echec (code {result.returncode}) sur les tags : {tags}")
        sys.exit(result.returncode)
    print(f"\n[OK] Termine : {tags}")

def main():
    p = argparse.ArgumentParser(
        description="Deploie la base vulnerable (radvd/FRR/Kea). Durcissement : voir harden.sh.")
    p.add_argument("phase", choices=list(PHASES.keys()) + ["check"])
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if args.phase == "check":
        run_tags(PHASES["vulnerable"], check=True)
        return
    run_tags(PHASES[args.phase], check=args.dry_run)

if __name__ == "__main__":
    main()