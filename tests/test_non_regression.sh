#!/bin/sh
# test_non_regression.sh — Phase 5.3 : verifie l'absence de faux positifs apres durcissement.
# Le RA legitime, l'adresse SLAAC et la joignabilite du routeur doivent toujours fonctionner.
# Retourne 0 si tout est OK, 1 sinon. A lancer : sudo ./tests/test_non_regression.sh
set -u
VICTIM="${VICTIM:-clab-projet10-ipv6-hote-a}"
ROUTER="${ROUTER:-2001:db8:10:1::1}"
IFACE="${IFACE:-eth1}"
rc=0

echo "[1/3] Adresse SLAAC legitime (2001:db8:10:1:...) presente sur $VICTIM ?"
if docker exec "$VICTIM" ip -6 addr show dev "$IFACE" scope global | grep -q "2001:db8:10:1:"; then
  echo "      OK : adresse SLAAC legitime presente"
else
  echo "      ECHEC : pas d'adresse SLAAC legitime (RA legitime bloque par erreur ?)"; rc=1
fi

echo "[2/3] Route par defaut legitime presente ?"
if docker exec "$VICTIM" ip -6 route show default | grep -q "default"; then
  echo "      OK : route par defaut presente"
else
  echo "      ECHEC : aucune route par defaut"; rc=1
fi

echo "[3/3] Routeur $ROUTER joignable ?"
if docker exec "$VICTIM" ping6 -c 3 -w 5 "$ROUTER" >/dev/null 2>&1; then
  echo "      OK : ping routeur reussi"
else
  echo "      ECHEC : routeur injoignable"; rc=1
fi

if [ "$rc" -eq 0 ]; then
  echo "NON-REGRESSION : OK - aucun faux positif, le trafic legitime passe toujours."
else
  echo "NON-REGRESSION : ECHEC - le durcissement casse du trafic legitime."
fi
exit $rc