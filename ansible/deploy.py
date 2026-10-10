#!/usr/bin/env python3
import argparse, subprocess, sys
from pathlib import Path
ANSIBLE_DIR = Path(__file__).parent
PLAYBOOK = ANSIBLE_DIR / "site.yml"
PHASES = {
    "vulnerable": ["phase1"],
    "harden": ["phase4"],
    "reset": ["reset"],
    "all": ["phase1", "phase4"],
}

def run_tags(tags, check=False):
    cmd = ["ansible-playbook", str(PLAYBOOK), "--tags", ",".join(tags)]
    if check:
        cmd += ["--check", "--diff"]
    print(f"\n>>> {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=ANSIBLE_DIR)
    if result.returncode != 0:
        print(f"\n❌ Échec (code {result.returncode}) sur les tags : {tags}")
        sys.exit(result.returncode)
    print(f"\n✅ Terminé : {tags}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("phase", choices=list(PHASES.keys()) + ["check"])
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if args.phase == "check":
        run_tags(PHASES["all"], check=True)
        return
    run_tags(PHASES[args.phase], check=args.dry_run)
if __name__ == "__main__":
    main()
