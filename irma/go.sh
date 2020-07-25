#!/bin/bash

vboxmanage controlvm ansible_brainirma_1577541833257_2837 poweroff 2>/dev/null

vboxmanage snapshot ansible_brainirma_1577541833257_2837 restore default
cd ansible/
python irma-ansible.py environments/allinone_prod.yml playbooks/playbook.yml
