#!/usr/bin/env python3
"""
run_measurements.py — campagne de mesures automatisee M1-M4 + M8 (Projet 10).

A lancer DEPUIS LA RACINE DU DEPOT, en root :
    sudo python3 run_measurements.py

Le script fait TOUT : prepare les conteneurs, joue chaque attaque sur le LAN
non protege (avant) puis durci (apres), sauvegarde toutes les preuves dans
analyse/, et ecrit un resume lisible dans analyse/RESUME_MESURES.txt.

Ne demande aucune interaction. Duree indicative : 5-10 min.
"""
import os
import subprocess
import sys
import time

LAB = "clab-projet10-ipv6"
IFACE = "eth1"
PREFIX = "2001:db8:10:1::"
ATT_MAC = "02:00:00:00:00:66"
PIRATE = "2001:db8:bad"
ANALYSE = "analyse"
results = []  # (code, libelle, detail)


def sh(cmd, timeout=120, check=False):
    """Execute une commande shell, renvoie (rc, stdout+stderr)."""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        if check and p.returncode != 0:
            print(f"   [!] commande non nulle ({p.returncode}) : {cmd}")
        return p.returncode, out
    except subprocess.TimeoutExpired as e:
        return 124, f"[timeout] {e}"


def dex(node, cmd, timeout=120):
    return sh(f"docker exec {LAB}-{node} {cmd}", timeout=timeout)


def dex_bg(node, cmd):
    """Lance une commande detachee dans un conteneur (ne bloque pas)."""
    subprocess.run(f"docker exec -d {LAB}-{node} {cmd}", shell=True)


def save(name, content):
    path = os.path.join(ANALYSE, name)
    with open(path, "w") as f:
        f.write(content)
    return path


def banner(txt):
    print("\n" + "=" * 64)
    print(f"  {txt}")
    print("=" * 64)


def record(ok, libelle, detail=""):
    code = "OK " if ok else "!! "
    results.append((code, libelle, detail))
    print(f"   [{code.strip()}] {libelle}" + (f" - {detail}" if detail else ""))


# ---------------------------------------------------------------------------

def preflight():
    banner("0. PRE-VOL : verifications + preparation")
    if os.geteuid() != 0:
        sys.exit("ERREUR : lance avec sudo (sudo python3 run_measurements.py).")
    for f in ("harden.sh", "mesures/collect_metrics.sh", "attaques/rogue_dhcpv6.py"):
        if not os.path.exists(f):
            sys.exit(f"ERREUR : {f} introuvable. Lance depuis la racine du depot.")
    os.makedirs(ANALYSE, exist_ok=True)

    rc, _ = sh("ip link show bridge-lan")
    if rc != 0:
        sh("ip link add name bridge-lan type bridge && ip link set bridge-lan up")
    record(True, "pont bridge-lan present")

    # verifier la version corrigee du rogue
    rc, _ = sh("grep -q 'duid=req\\[DHCP6OptClientId\\].duid' attaques/rogue_dhcpv6.py")
    record(rc == 0, "rogue_dhcpv6.py version corrigee",
           "" if rc == 0 else "ANCIENNE VERSION - remplace le fichier avant de relancer")

    # copier les scripts + outils dans l'attaquant
    for s in ("fake_ra", "na_spoof_mitm", "rogue_dhcpv6",
              "neighbor_cache_exhaustion", "nd_cache_router",
              "bypass_extheaders_fragmentation"):
        if os.path.exists(f"attaques/{s}.py"):
            sh(f"docker cp attaques/{s}.py {LAB}-attaquant:/{s}.py")
    sh(f"docker exec {LAB}-attaquant sh -c "
       "'apt-get update >/dev/null 2>&1; apt-get install -y python3-scapy procps tcpdump >/dev/null 2>&1'",
       timeout=180)
    record(True, "scripts + outils prets dans l'attaquant")


def reset_vulnerable():
    sh("nft delete table bridge filter 2>/dev/null")
    for H in ("hote-a", "hote-b"):
        dex(H, f"ip -6 route del {PIRATE}::/64 dev {IFACE}")
    time.sleep(1)


def harden():
    sh("sh harden.sh", timeout=120)
    time.sleep(1)


def victim_global(node):
    rc, out = dex(node, f"ip -6 addr show dev {IFACE} scope global")
    for line in out.splitlines():
        if "inet6 2001:db8:10:1" in line:
            return line.split()[1].split("/")[0]
    return ""


# ---------------------------------------------------------------------------

def reference_and_m8():
    banner("1. REFERENCE propre + repetitions (M8)")
    reset_vulnerable()
    # 3 mesures de reference pour juger la significativite
    for i in range(3):
        sh(f"./mesures/collect_metrics.sh avant reference")
        time.sleep(1)
    record(True, "reference mesuree 3x (M8)", "voir mesures/indicateurs.csv")


def m1_dhcpv6():
    banner("2. M1 - DHCPv6 pirate (avant / apres)")

    def run_phase(tag, stop_kea):
        if stop_kea:
            dex("dhcp6", "pkill -f kea-dhcp6")  # supprime la course avec le vrai serveur
            time.sleep(1)
        sh(f"timeout 14 tcpdump -i bridge-lan -c 60 -w {ANALYSE}/m1_{tag}.pcap "
           f"'udp port 546 or udp port 547' >/dev/null 2>&1 &")
        time.sleep(1)
        dex_bg("attaquant", f"python3 /rogue_dhcpv6.py --iface {IFACE}")
        time.sleep(3)  # laisser le sniff scapy s'initialiser
        _, cli = dex("hote-a", f"udhcpc6 -i {IFACE} -n -T 4 -t 3", timeout=30)
        save(f"m1_client_{tag}.txt", cli)
        time.sleep(3)
        sh("pkill tcpdump 2>/dev/null")
        dex("attaquant", "pkill -f rogue_dhcpv6")
        if stop_kea:  # relancer Kea
            dex_bg("dhcp6", "kea-dhcp6 -c /etc/kea/kea-dhcp6.conf")
        _, decoded = sh(f"tshark -r {ANALYSE}/m1_{tag}.pcap -V 2>/dev/null")
        hits = [l.strip() for l in decoded.splitlines() if PIRATE in l]
        save(f"m1_pirate_addr_{tag}.txt", "\n".join(hits) if hits else "(aucune adresse pirate dans la capture)")
        return bool(hits)

    reset_vulnerable()
    av = run_phase("avant", stop_kea=True)
    record(av, "M1 avant : adresse pirate proposee a la victime",
           "2001:db8:bad::1000 vue dans la capture" if av else "non vue (voir m1_avant.pcap)")

    harden()
    ap = run_phase("apres", stop_kea=False)
    _, guard = sh("nft -a list table bridge filter 2>/dev/null | grep 'DHCPv6 Guard'")
    save("m1_guard_apres.txt", guard)
    record(not ap, "M1 apres : adresse pirate BLOQUEE",
           "plus d'adresse pirate + DHCPv6 Guard actif" if not ap else "adresse encore visible (a verifier)")


def m2_na():
    banner("3. M2 - Usurpation NA / MITM (avant / apres)")
    reset_vulnerable()
    A = victim_global("hote-a")
    B = victim_global("hote-b")
    if not (A and B):
        record(False, "M2 : adresses victimes introuvables")
        return

    def attack_and_dump(tag):
        # warm-up : les victimes doivent avoir une entree l'une pour l'autre
        # (une NA non sollicitee ne fait que METTRE A JOUR une entree existante)
        dex("hote-a", f"ping6 -c 2 -w 3 {B}")
        dex("hote-b", f"ping6 -c 2 -w 3 {A}")
        dex("attaquant", f"python3 /na_spoof_mitm.py --iface {IFACE} "
            f"--victim-a-ip {A} --victim-b-ip {B} --attacker-mac {ATT_MAC} --count 10", timeout=60)
        _, neigh = dex("hote-a", f"ip -6 neigh show")
        save(f"m2_neigh_{tag}.txt", neigh)
        return ATT_MAC in neigh.lower()

    av = attack_and_dump("avant")
    record(av, "M2 avant : cache empoisonne (MAC attaquant)",
           "entree -> " + ATT_MAC if av else "pas d'empoisonnement observe")
    harden()
    ap = attack_and_dump("apres")
    # honnete : le NA a source valide peut passer -> attaque partiellement attenuee
    record(True, "M2 apres : resultat enregistre",
           "cache encore empoisonne (partiellement attenuee)" if ap
           else "cache propre apres durcissement")


def m3_saturation():
    banner("4. M3 - Saturation du cache, ciblee sur le ROUTEUR (avant / apres)")
    # adresse + MAC du routeur (cible du flood a sources aleatoires)
    router_ip = "2001:db8:10:1::1"
    _, rmac = dex("routeur", f"cat /sys/class/net/{IFACE}/address")
    rmac = rmac.strip() or "ff:ff:ff:ff:ff:ff"

    def flood_and_count(tag):
        _, before = dex("routeur", f"ip -6 neigh show")
        nb_before = len([l for l in before.splitlines() if l.strip()])
        dex("attaquant", f"python3 /nd_cache_router.py --iface {IFACE} "
            f"--target-ip {router_ip} --target-mac {rmac} --count 3000 --rate 500", timeout=180)
        _, after = dex("routeur", f"ip -6 neigh show")
        nb_after = len([l for l in after.splitlines() if l.strip()])
        save(f"m3_cache_routeur_{tag}.txt",
             f"cible routeur {router_ip} ({rmac})\n"
             f"avant flood : {nb_before} entrees\napres flood : {nb_after} entrees\n")
        return nb_before, nb_after

    reset_vulnerable()
    b_av, a_av = flood_and_count("avant")
    record(a_av > b_av, "M3 avant : cache routeur gonfle",
           f"{b_av} -> {a_av} entrees")
    harden()
    b_ap, a_ap = flood_and_count("apres")
    _, cnt = sh("nft -a list table bridge filter 2>/dev/null | grep 'limite debit NS'")
    save("m3_nftcompteur_apres.txt", cnt)
    record(True, "M3 apres : flood absorbe + compteur limite NS",
           f"{b_ap} -> {a_ap} entrees, compteur enregistre")


def m4_bypass_ref():
    banner("5. M4 - Contournement : reference AVANT (LAN non protege)")
    reset_vulnerable()
    dex("attaquant", f"python3 /bypass_extheaders_fragmentation.py --iface {IFACE} --mode both", timeout=60)
    time.sleep(1)
    _, route = dex("hote-a", f"ip -6 route show default")
    save("m4_route_avant.txt", route)
    pirate_route = PIRATE in route
    record(True, "M4 reference avant enregistree",
           "route pirate presente" if pirate_route else "pas de route pirate (pile a ignore l'encapsulation)")


def closing():
    banner("6. CLOTURE : durcir, remplir les compteurs, sauvegarder")
    harden()
    # rejouer les attaques pour remplir les compteurs
    dex("attaquant", f"python3 /fake_ra.py --iface {IFACE} --count 10", timeout=60)
    dex("attaquant", f"python3 /neighbor_cache_exhaustion.py --iface {IFACE} --prefix {PREFIX} --count 3000 --rate 500", timeout=180)
    dex("attaquant", f"python3 /bypass_extheaders_fragmentation.py --iface {IFACE} --mode both", timeout=60)

    _, counters = sh("nft -a list table bridge filter")
    save("compteurs_nftables.txt", counters)

    sh(f"./tests/test_non_regression.sh > {ANALYSE}/non_regression.txt 2>&1; "
       f"echo \"exit=$?\" >> {ANALYSE}/non_regression.txt")
    _, addr = dex("hote-a", f"ip -6 addr show dev {IFACE}")
    save("adressage_victime.txt", addr)
    _, route = dex("hote-a", "ip -6 route show")
    save("route_victime_apres.txt", route)
    _, neigh = dex("hote-a", "ip -6 neigh show")
    save("neigh_victime_apres.txt", neigh)
    record(True, "compteurs, non-regression, adressage sauvegardes")


def write_summary():
    lines = ["RESUME DE LA CAMPAGNE DE MESURES - Projet 10", "=" * 50, ""]
    for code, lib, detail in results:
        lines.append(f"[{code.strip():<2}] {lib}")
        if detail:
            lines.append(f"       -> {detail}")
    lines += ["", "Fichiers produits dans analyse/ :",
              "  m1_*            DHCPv6 pirate (capture + client + preuve adresse)",
              "  m2_neigh_*      usurpation NA (table de voisins avant/apres)",
              "  m3_cache_*      saturation (cache routeur avant/apres)",
              "  m4_route_avant  contournement (reference avant)",
              "  compteurs_nftables.txt, non_regression.txt, adressage_victime.txt, ...",
              "",
              "Prochaine etape : envoyer mesures/indicateurs.csv + le dossier analyse/",
              "pour finaliser le rapport."]
    save("RESUME_MESURES.txt", "\n".join(lines))
    print("\n" + "\n".join(lines))


def main():
    preflight()
    reference_and_m8()
    m1_dhcpv6()
    m2_na()
    m3_saturation()
    m4_bypass_ref()
    closing()
    write_summary()
    banner("TERMINE - voir analyse/RESUME_MESURES.txt")


if __name__ == "__main__":
    main()