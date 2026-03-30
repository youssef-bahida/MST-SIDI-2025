# -*- coding: utf-8 -*-
"""
KP-ABE Hybride Simplifié pour Débutants
Chiffrement hybride : KP-ABE + AES
Auteur : Simplifié pour débutants
"""

from charm.toolbox.pairinggroup import PairingGroup, GT, extract_key
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.schemes.abenc.abenc_lsw08 import KPabe

# Mode debug pour afficher les étapes
debug = True

# ----------------------------
# Classe pour le chiffrement hybride
# ----------------------------
class HybridABEnc:
    """
    Cette classe permet de chiffrer un message de n'importe quelle longueur
    en utilisant KP-ABE + AES.
    """

    def __init__(self, abe_scheme, groupObj):
        """
        Initialisation :
        - abe_scheme : l'instance du schéma KP-ABE (ici KPabe)
        - groupObj : groupe de pairage pour le KP-ABE
        """
        self.abe = abe_scheme
        self.group = groupObj

    # Setup : génère les clés publiques et maîtres du KP-ABE
    def setup(self):
        return self.abe.setup()

    # KeyGen : génère la clé secrète utilisateur pour une politique d'accès
    def keygen(self, pk, mk, policy):
        return self.abe.keygen(pk, mk, policy)

    # Encrypt : chiffre un message M avec un ensemble d'attributs
    def encrypt(self, pk, M, attributes):
        # 1. Générer une clé aléatoire dans GT pour AES
        session_key = self.group.random(GT)

        # 2. Chiffrer la clé avec KP-ABE
        c1 = self.abe.encrypt(pk, session_key, attributes)

        # 3. Chiffrement symétrique AES avec cette clé
        cipher = AuthenticatedCryptoAbstraction(extract_key(session_key))
        c2 = cipher.encrypt(M)

        # 4. Retourner le "hybride" : clé KP-ABE + message AES
        return {'c1': c1, 'c2': c2}

    # Decrypt : déchiffre le message avec la clé secrète
    def decrypt(self, ct, sk):
        # 1. Déchiffrer la clé AES avec KP-ABE
        session_key = self.abe.decrypt(ct['c1'], sk)

        # 2. Déchiffrer le message avec AES
        cipher = AuthenticatedCryptoAbstraction(extract_key(session_key))
        return cipher.decrypt(ct['c2'])


# ----------------------------
# Exemple d'utilisation
# ----------------------------
def main():
    # 1. Créer le groupe de pairage et le schéma KP-ABE
    group = PairingGroup('SS512')
    kpabe = KPabe(group)
    hyb_abe = HybridABEnc(kpabe, group)

    # 2. Définir la politique d'accès et les attributs
    access_policy = '((ONE or TWO) and THREE)'  # politique KP-ABE
    attributes = ['ONE', 'TWO', 'THREE']       # attributs pour le chiffrement

    # 3. Message à chiffrer (en bytes !)
    message = b"hello world this is an important message."

    # 4. Générer clés publiques et maîtres
    pk, mk = hyb_abe.setup()
    if debug: print("Clés générées.")

    # 5. Générer clé secrète pour l'utilisateur
    sk = hyb_abe.keygen(pk, mk, access_policy)
    if debug: print("Clé secrète générée.")

    # 6. Chiffrement
    ct = hyb_abe.encrypt(pk, message, attributes)
    if debug: print("Message chiffré :", ct)

    # 7. Déchiffrement
    decrypted = hyb_abe.decrypt(ct, sk)
    if debug: print("Message déchiffré :", decrypted)

    # 8. Vérification
    assert decrypted == message, "Erreur : déchiffrement incorrect !"
    print("Déchiffrement réussi ✅")


if __name__ == "__main__":
    main()