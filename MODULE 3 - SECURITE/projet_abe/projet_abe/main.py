# -*- coding: utf-8 -*-
"""
user_test_blocks.py
Tests séparés pour KP-ABE et CP-ABE avec le même capteur
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
from charm.toolbox.pairinggroup import PairingGroup
from schemas.kp_abe import HybridABEnc
from schemas.cp_abe import HybridCPABE
from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from Cloud.cloud import *  # cloud.py
import json
from IoT.capteur import Sensor
from User.user import User  # classe User pour les tests de déchiffrement

# ----------------------------
# Initialisation du groupe de pairage
# ----------------------------
group = PairingGroup('SS512')

# ----------------------------
# Création d'un capteur unique
# ----------------------------
sensor1 = Sensor(
    sensor_id="S1",
    attributes=["ONE", "TWO", "THREE"],
    access_policy="((ONE or TWO) and THREE)",
    groupObj=group,
    scheme="kp"  # Schéma initial pour le sensor (sera ignoré dans les tests séparés)
)

# ----------------------------
# TEST 1 : KP-ABE
# ----------------------------
print("=== TEST KP-ABE ===\n")

# Créer un utilisateur KP-ABE
user_kp = User(
    user_id="Alice",
    scheme="kp",
    groupObj=group,
    access_policy="((ONE or TWO) and THREE)"
)

# Générer les données du capteur
data_kp = sensor1.generate_data()

# Chiffrer avec le pk exact de l'utilisateur
ct_kp = user_kp.kpabe.encrypt(user_kp.pk, json.dumps(data_kp).encode('utf-8'), sensor1.attributes)

# Envoyer au cloud
send_to_cloud({
    "sensor_id": sensor1.sensor_id,
    "scheme": "kp",
    "timestamp": data_kp["timestamp"],
    "ciphertext": ct_kp
})

# Déchiffrement par Alice
print("\n--- Déchiffrement par Alice (KP-ABE) ---")
decrypted_kp = user_kp.decrypt_from_cloud(0)
print("Données déchiffrées :", decrypted_kp)

# ----------------------------
# TEST 2 : CP-ABE
# ----------------------------
print("\n=== TEST CP-ABE ===\n")

# Créer un utilisateur CP-ABE
user_cp = User(
    user_id="Bob",
    scheme="cp",
    groupObj=group,
    attributes=["ONE", "TWO", "THREE"]
)

# Générer les mêmes données du capteur
data_cp = sensor1.generate_data()

# Chiffrer avec le pk exact de l'utilisateur CP-ABE
ct_cp = user_cp.cpabe.encrypt(user_cp.pk, json.dumps(data_cp).encode('utf-8'), sensor1.attributes)

# Envoyer au cloud
send_to_cloud({
    "sensor_id": sensor1.sensor_id,
    "scheme": "cp",
    "timestamp": data_cp["timestamp"],
    "ciphertext": ct_cp
})

# Déchiffrement par Bob
print("\n--- Déchiffrement par Bob (CP-ABE) ---")
decrypted_cp = user_cp.decrypt_from_cloud(1)
print("Données déchiffrées :", decrypted_cp)