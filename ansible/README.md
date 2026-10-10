# Automatisation Ansible — Projet 10
Installation :
pip3 install ansible
ansible-galaxy collection install -r requirements.yml
(requirements.yml installe community.docker ET community.general —
ce dernier fournit le module apk nécessaire car le conteneur routeur
tourne sous Alpine Linux, pas Debian/Ubuntu.)
Utilisation :
python3 deploy.py vulnerable # Phase 1
python3 deploy.py harden # Phase 4
python3 deploy.py reset # revenir à l'état vulnérable
python3 deploy.py all # les deux à la suite
python3 deploy.py check # dry-run (--check --diff)
Équivalent direct :
ansible-playbook site.yml --tags phase1
ansible-playbook site.yml --tags phase4
Note : ces conteneurs n'ont pas de systemd, donc les rôles radvd/frr/kea
utilisent des commandes directes (pgrep + command) plutôt que le module
service: d'Ansible.