# -*- coding: utf-8 -*-
"""
passerelle.py
Passerelle IoT :
- Reçoit les données chiffrées des capteurs via CoAP
- Peut gérer plusieurs protocoles (CoAP, MQTT, etc.)
- Envoie les données vers cloud.py
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
import json
from coapthon.server.coap import CoAP
from coapthon.resources.resource import Resource

# On importera cloud.py pour envoyer les données
from Cloud.cloud import send_to_cloud  # à créer dans cloud.py

# ----------------------------
# Resource CoAP pour recevoir les données
# ----------------------------
class SensorResource(Resource):
    def __init__(self, name="SensorResource", coap_server=None):
        super(SensorResource, self).__init__(name, coap_server, visible=True,
                                             observable=True, allow_children=True)
    
    def render_POST(self, request):
        """
        Cette méthode est appelée quand un capteur fait un POST sur le serveur CoAP
        """
        try:
            payload = request.payload
            data = json.loads(payload)

            print(f"[Passerelle] Données reçues du capteur {data.get('sensor_id')}")
            
            # Ici, on pourrait déchiffrer directement si on avait la clé
            # Pour l'instant on transmet telles quelles au cloud
            send_to_cloud(data)

            return self, 201  # Code CoAP Created
        except Exception as e:
            print(f"[Passerelle] Erreur lors du traitement des données : {e}")
            return self, 500


# ----------------------------
# Serveur CoAP
# ----------------------------
class GatewayServer(CoAP):
    def __init__(self, host="0.0.0.0", port=5683):
        super(GatewayServer, self).__init__((host, port))
        self.add_resource('sensor/data/', SensorResource())
        print(f"[Passerelle] Serveur CoAP démarré sur {host}:{port}")

    def shutdown(self):
        print("[Passerelle] Arrêt du serveur CoAP")
        super(GatewayServer, self).shutdown()


# ----------------------------
# Exemple d'utilisation
# ----------------------------
if __name__ == "__main__":
    try:
        server = GatewayServer(host="127.0.0.1", port=5683)
        server.listen(10)  # écoute avec 10 secondes de timeout
    except KeyboardInterrupt:
        server.shutdown()