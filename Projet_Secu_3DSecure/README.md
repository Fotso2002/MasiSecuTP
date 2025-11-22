# 🛡️ Projet de Sécurité : Serveur HTTPS & 3D-Secure

Ce projet implémente une architecture de paiement sécurisé simulant le protocole **3D-Secure**. Il met en œuvre des concepts de cryptographie (SSL/TLS, PKI, Hachage, Signature Numérique).

## 👥 Membres du groupe
* Stanella
* Franck
* Cabrel

---

## 🏗️ Architecture Globale

Le système est composé de 4 entités distinctes qui communiquent via le réseau :

1.  **Serveur HTTPS (Marchand)** - `Port 8043`
    * Site web de réservation de vacances.
    * Authentifie les clients (Login/Mdp).
    * Initie la demande de paiement vers l'ACQ.
2.  **Serveur ACQ (Banque du Marchand)** - `Port 9091`
    * Intermédiaire technique.
    * Reçoit la demande du site et la transfère à la banque du client (ACS).
3.  **Serveur ACS (Banque du Client)** - `Ports 9090 & 9092`
    * **Port 9090 (Money)** : Vérifie la validité du paiement auprès de l'ACQ.
    * **Port 9092 (Auth)** : Authentifie le client via l'application externe et génère un Token signé.
4.  **Client Application (App Tiers)**
    * Petit programme Java utilisé par le client pour signer sa demande et obtenir son Token.

---

## 📜 Historique des étapes réalisées

### 🔹 Étape 1 : Infrastructure PKI (Clés et Certificats)
Nous avons généré une infrastructure à clés publiques (PKI) pour sécuriser les échanges.
* **Dossier :** `keystores/`
* **Fichiers générés :**
    * `server.jks`, `acq.jks`, `acs.jks`, `client.jks` : Identités privées (Clés RSA 2048 bits).
    * `truststore.jks` : Liste de confiance commune (contient les certificats publics de tous les acteurs).

### 🔹 Étape 2 : Socle Commun (`src/common/`)
Création des outils partagés pour éviter la duplication de code.
* `NetworkUtils.java` : Permet de créer des contextes SSL/TLS complexes (chargement Keystore + Truststore) en une ligne.
* `CryptoUtils.java` :
    * **Hachage** : SHA-256 + Salt (pour les mots de passe).
    * **Signature** : SHA-256 with RSA (pour signer/vérifier les tokens en Phase 2).

### 🔹 Étape 3 : Phase 1 (HTTPS & Boucle SSL)
Mise en place de la communication sécurisée de bout en bout.
1.  **Site Web** : Affiche un formulaire, vérifie le login hashé, et contacte l'ACQ.
2.  **Chaîne de liaison** : `Mapsur` -> `HTTPS` -> `ACQ` -> `ACS`.
3.  **Test réussi** : Le site web affiche "ACK from ACS", prouvant que le message a traversé tout le réseau.

### 🔹 Étape 4 : Phase 2 (3D-Secure & Token) - *En cours*
Implémentation de la double authentification.
1.  **ClientApp** : Envoie "Carte + Date" signé avec sa clé privée vers l'ACS (Port 9092).
2.  **ACS (Auth)** : Vérifie la signature du client, génère un Token, le signe, et le renvoie.
3.  *(À faire)* : Intégrer la saisie de ce Token sur le site web pour validation finale.

---

## 🚀 Guide de Démarrage

### 1. Nettoyage et Compilation
À exécuter à la racine du projet (Git Bash) :
```bash
rm -rf bin
mkdir bin
javac -d bin -sourcepath src src/common/*.java src/server_acs/*.java src/server_acq/*.java src/server_https/*.java src/app_client/*.java