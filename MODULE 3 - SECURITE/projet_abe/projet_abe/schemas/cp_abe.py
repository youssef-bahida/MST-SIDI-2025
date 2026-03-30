# -*- coding: utf-8 -*-
"""
Hybrid CP-ABE BSW07 + AES pour débutants
Chiffrement hybride : CP-ABE BSW07 + AES
"""

from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.core.math.pairing import hashPair as sha2 # Fonction de hachage pour dériver une clé symétrique à partir d'un élément de GT.

debug = True 

# ----------------------------
# Classe Hybride CP-ABE BSW07
# ----------------------------
class HybridCPABE(ABEnc):
    """
    Classe pour chiffrer/déchiffrer un message de n'importe quelle longueur
    avec CP-ABE BSW07 + AES.
    """

    def __init__(self, scheme, groupObj):
        ABEnc.__init__(self)
        self.abenc = scheme
        self.group = groupObj

    def setup(self):
        return self.abenc.setup() # Retourne (pk, mk)

    def keygen(self, pk, mk, attributes):
        """
        Génère la clé utilisateur en fonction des attributs
        pour CP-ABE BSW07.
        """
        return self.abenc.keygen(pk, mk, attributes)

    def encrypt(self, pk, data , policy):
        """
        Chiffre le message M selon la politique.
        1. Génère une clé de session aléatoire (GT)
        2. Chiffre la clé avec CP-ABE BSW07
        3. Chiffre le message avec AES + clé de session
        """
        # Clé de session aléatoire
        session_key = self.group.random(GT)

        # Chiffrement de la clé de session via CP-ABE BSW07
        c1 = self.abenc.encrypt(pk, session_key, policy)

        # Chiffrement symétrique AES
        cipher = AuthenticatedCryptoAbstraction(sha2(session_key))
        c2 = cipher.encrypt(data)

        return {'c1': c1, 'c2': c2}

    def decrypt(self, pk, sk, ct):
        """
        Déchiffre le message hybride :
        1. Déchiffre la clé AES avec CP-ABE
        2. Déchiffre le message avec AES
        """
        session_key = self.abenc.decrypt(pk, sk, ct['c1'])
        if session_key is False:
            raise Exception("Erreur : impossible de déchiffrer la clé !")

        cipher = AuthenticatedCryptoAbstraction(sha2(session_key))
        return cipher.decrypt(ct['c2'])


# ----------------------------
# Exemple d'utilisation
# ----------------------------
def main():
    group = PairingGroup('SS512')

    # Initialisation CP-ABE BSW07
    cpabe = CPabe_BSW07(group)
    hyb_cpabe = HybridCPABE(cpabe, group)

    # Politique et attributs
    policy = '((ONE or TWO) and THREE)'  # politique dans le ciphertext
    attributes = ['ONE', 'TWO', 'THREE']  # attributs pour la clé utilisateur

    message = b"Bonjour, ceci est un message important."

    # Setup
    pk, mk = hyb_cpabe.setup()
    if debug: print("Clés générées.")

    # Génération de la clé utilisateur
    sk = hyb_cpabe.keygen(pk, mk, attributes)
    if debug: print("Clé utilisateur générée.")

    # Chiffrement
    ct = hyb_cpabe.encrypt(pk, message, policy)
    if debug: print("Message chiffré :", ct)

    # Déchiffrement
    decrypted = hyb_cpabe.decrypt(pk, sk, ct)
    if debug: print("Message déchiffré :", decrypted)

    # Vérification
    assert decrypted == message, "Erreur : déchiffrement incorrect !"
    print("Déchiffrement réussi ✅ :", decrypted)


if __name__ == "__main__":
    main()