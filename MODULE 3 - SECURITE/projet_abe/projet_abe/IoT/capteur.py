# -*- coding: utf-8 -*-
"""
sensor.py
Simulation d'un capteur IoT :
- Génère des données toutes les 5 secondes
- Chiffre ces données avec KP-ABE ou CP-ABE + AES
- Prépare les données pour l'envoi à une passerelle
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
# Permet d'importer les classes de schemas même si on est dans un sous-dossier
import time
import random
import json
from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.schemes.abenc.abenc_lsw08 import KPabe
# Import des classes hybrides depuis vos fichiers séparés
from schemas.kp_abe import HybridABEnc  # classe KP-ABE hybride
from schemas.cp_abe import HybridCPABE  # classe CP-ABE BSW07 hybride

from coapthon.client.helperclient import HelperClient # Client CoAP pour envoyer les données à la passerelle


# ----------------------------
# Classe Capteur
# ----------------------------
class Sensor:
    def __init__(self, sensor_id, attributes, access_policy, groupObj, scheme="kp"):
        """
        Initialisation du capteur :
        - sensor_id : identifiant du capteur
        - attributes : attributs pour le chiffrement KP-ABE ou CP-ABE
        - access_policy : politique d'accès pour le déchiffrement
        - groupObj : groupe de pairage
        - scheme : "kp" pour KP-ABE, "cp" pour CP-ABE
        """
        self.sensor_id = sensor_id
        self.attributes = attributes
        self.access_policy = access_policy
        self.group = groupObj
        self.scheme_type = scheme

        # Initialisation du schéma choisi
        if scheme == "kp":
            self.kpabe = HybridABEnc(KPabe(self.group), self.group)
            # Génération des clés publiques et maîtres
            self.pk, self.mk = self.kpabe.setup()
            self.sk = self.kpabe.keygen(self.pk, self.mk, self.access_policy)
        elif scheme == "cp":
            self.cpabe = HybridCPABE(CPabe_BSW07(self.group), self.group)
            # Génération des clés publiques et maîtres
            self.pk, self.mk = self.cpabe.setup()
            self.sk = self.cpabe.keygen(self.pk, self.mk, self.attributes)
        else:
            raise ValueError("Scheme doit être 'kp' ou 'cp'")

    def generate_data(self):
        """
        Simule les données du capteur :
        - température (°C) : 20 à 30
        - humidité (%) : 30 à 70
        """
        data = {
            "sensor_id": self.sensor_id,
            "temperature": round(random.uniform(20.0, 30.0), 2),
            "humidity": round(random.uniform(30.0, 70.0), 2),
            "timestamp": time.time()
        }
        return data

    def encrypt_data(self, data):
        """
        Chiffre les données avec le schéma choisi
        """
        data_bytes = json.dumps(data).encode('utf-8')
        if self.scheme_type == "kp":
            return self.kpabe.encrypt(self.pk, data_bytes, self.attributes)
        else:
            return self.cpabe.encrypt(self.pk, data_bytes, self.access_policy)

    def send_to_gateway(self, ct, host="localhost", port=5683, path="sensor/data"):
        """
        Envoie les données chiffrées au serveur/passerelle via CoAP POST
        - ct : dictionnaire contenant 'c1' et 'c2'
        - host, port : coordonnées de la passerelle CoAP
        - path : chemin sur lequel poster les données
        """
        try:
            client = HelperClient(server=(host, port))
            # Convertir le ciphertext en string JSON pour l'envoyer
            # Attention : certains éléments (GT) doivent être sérialisés en string
            def serialize(obj):
                # Si c'est un élément de pairing (GT), convertir en string hex
                try:
                    return obj.__str__()
                except:
                    return obj

            payload = json.dumps({
                "sensor_id": self.sensor_id,
                "c1": {k: serialize(v) for k, v in ct['c1'].items()},
                "c2": ct['c2'].hex()  # convertir bytes en hex string
            })

            client.post(path, payload)
            client.stop()
            print(f"[Capteur {self.sensor_id}] Données envoyées à la passerelle via CoAP")
        except Exception as e:
            print(f"[Capteur {self.sensor_id}] Erreur en envoyant les données : {e}")

    def run(self, interval=5):
        """
        Boucle principale du capteur :
        - génère des données toutes les 'interval' secondes
        - chiffre les données
        - affiche les données chiffrées
        """
        try:
            while True:
                data = self.generate_data()
                ct = self.encrypt_data(data)
                print(f"[Capteur {self.sensor_id}] Données générées : {data}")
                print(f"[Capteur {self.sensor_id}] Données chiffrées : {ct}\n")
                
                 # Envoi vers la passerelle
                self.send_to_gateway(ct, host="127.0.0.1", port=5683, path="sensor/data")
            
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Simulation arrêtée par l'utilisateur.")


# ----------------------------
# Exemple d'utilisation
# ----------------------------
if __name__ == "__main__":
    group = PairingGroup('SS512')

    # Exemple avec KP-ABE
    sensor1 = Sensor(
        sensor_id="S1",
        attributes=['ONE', 'TWO', 'THREE'],
        access_policy='((ONE or TWO) and THREE)',
        groupObj=group,
        scheme="kp"  # ou "cp" pour CP-ABE
    )

    sensor1.run(interval=5)