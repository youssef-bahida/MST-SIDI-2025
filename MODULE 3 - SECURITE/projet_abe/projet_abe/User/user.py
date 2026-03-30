# -*- coding: utf-8 -*-
"""
user.py
Classe utilisateur pour le cloud IoT avec KP-ABE ou CP-ABE
- Permet de gérer un utilisateur
- Déchiffre les données stockées dans le cloud
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
from charm.toolbox.pairinggroup import PairingGroup
from schemas.kp_abe import HybridABEnc
from schemas.cp_abe import HybridCPABE
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from Cloud.cloud import *  # cloud.py que nous avons créé
import json

# ----------------------------
# Classe User
# ----------------------------
class User:
    def __init__(self, user_id, scheme, groupObj, attributes=None, access_policy=None):
        """
        Initialisation de l'utilisateur
        - user_id : identifiant unique
        - scheme : "kp" ou "cp"
        - groupObj : groupe de pairage
        - attributes : attributs pour CP-ABE
        - access_policy : politique pour KP-ABE
        """
        self.user_id = user_id
        self.scheme_type = scheme
        self.group = groupObj
        self.attributes = attributes
        self.access_policy = access_policy

        # Génération des clés selon le schéma
        if scheme == "kp":
            self.kpabe = HybridABEnc(KPabe(self.group), self.group)
            self.pk, self.mk = self.kpabe.setup()
            self.sk = self.kpabe.keygen(self.pk, self.mk, self.access_policy)
        elif scheme == "cp":
            self.cpabe = HybridCPABE(CPabe_BSW07(self.group), self.group)
            self.pk, self.mk = self.cpabe.setup()
            self.sk = self.cpabe.keygen(self.pk, self.mk, self.attributes)
        else:
            raise ValueError("Le schéma doit être 'kp' ou 'cp'")

        # Enregistrement automatique dans le cloud
        register_user(self.user_id, self.scheme_type, self.pk, self.sk)

    def decrypt_from_cloud(self, record_index):
        """
        Déchiffre une entrée spécifique du cloud
        """
        record = cloud_storage[record_index]  # récupération du record
        if record["scheme"] != self.scheme_type:
            print(f"[Cloud] Schéma de l'utilisateur et du record ne correspondent pas !")
            return None

        ct = record["ciphertext"]
        try:
            if self.scheme_type == "kp":
                decrypted_bytes = self.kpabe.decrypt(ct, self.sk)
            else:
                decrypted_bytes = self.cpabe.decrypt(self.pk, self.sk, ct)
            decrypted_data = json.loads(decrypted_bytes.decode('utf-8'))
            print(f"[Cloud] Données déchiffrées pour {self.user_id} :", decrypted_data)
            return decrypted_data
        except Exception as e:
            print(f"[Cloud] Erreur de déchiffrement pour {self.user_id} :", str(e))
            return None


# ----------------------------
# Tests intégrés pour User.py
# ----------------------------
if __name__ == "__main__":
    print("=== TESTS UTILISATEUR CLOUD IoT ===\n")

    group = PairingGroup('SS512')

    # ----------------------------
    # Test KP-ABE
    # ----------------------------
    print("--- Test KP-ABE ---\n")
    user_kp = User(
        user_id="Alice",
        scheme="kp",
        groupObj=group,
        access_policy="((ONE or TWO) and THREE)"
    )

    # Simuler données capteur
    sensor_data_kp = {
        "sensor_id": "S1",
        "temperature": 25.3,
        "humidity": 55.2,
        "timestamp": 1234567890
    }

    # Chiffrement avec le pk exact de l'utilisateur
    ct_kp = user_kp.kpabe.encrypt(user_kp.pk, json.dumps(sensor_data_kp).encode('utf-8'), ["ONE", "TWO", "THREE"])
    send_to_cloud({
        "sensor_id": "S1",
        "scheme": "kp",
        "timestamp": sensor_data_kp["timestamp"],
        "ciphertext": ct_kp
    })

    # Déchiffrement par Alice
    user_kp.decrypt_from_cloud(0)

    # ----------------------------
    # Test CP-ABE
    # ----------------------------
    print("\n--- Test CP-ABE ---\n")
    user_cp = User(
        user_id="Bob",
        scheme="cp",
        groupObj=group,
        attributes=["ONE", "TWO", "THREE"]
    )

    sensor_data_cp = {
        "sensor_id": "S2",
        "temperature": 28.1,
        "humidity": 60.5,
        "timestamp": 1234567891
    }

    ct_cp = user_cp.cpabe.encrypt(user_cp.pk, json.dumps(sensor_data_cp).encode('utf-8'), ["ONE", "TWO", "THREE"])
    send_to_cloud({
        "sensor_id": "S2",
        "scheme": "cp",
        "timestamp": sensor_data_cp["timestamp"],
        "ciphertext": ct_cp
    })

    # Déchiffrement par Bob
    user_cp.decrypt_from_cloud(1)

    # ----------------------------
    # Test déchiffrement incorrect
    # ----------------------------
    print("\n--- Tentative de déchiffrement incorrect ---")
    print("Bob tente de déchiffrer la donnée KP-ABE (doit échouer)")
    user_cp.decrypt_from_cloud(0)