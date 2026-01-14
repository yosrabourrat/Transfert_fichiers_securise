# Transfert de Fichiers Sécurisé - Projet Java

*Réalisé par* : Yosra BOURRAT et Fatima Zahra NACIRI␣

*Encadré par* : M.BENTAJER

## Contexte : Ce projet consiste à créer une **application Client-Serveur en Java** pour le transfert de fichiers de manière sécurisée.

Le client envoie un fichier vers le serveur en utilisant :

* **TCP** pour la communication
* **AES** pour le chiffrement des fichiers
* **SHA-256** pour vérifier l’intégrité des fichiers

---

## Exigences de l’exercice

1. Le serveur doit :

   * Écouter les connexions sur un port défini
   * Authentifier les utilisateurs
   * Recevoir les métadonnées et le fichier chiffré
   * Déchiffrer le fichier et vérifier son hash
   * Retourner `TRANSFER_SUCCESS` ou `TRANSFER_FAIL`

2. Le client doit :

   * Permettre à l’utilisateur de saisir l’IP, le port, le login, le mot de passe et le chemin du fichier
   * Calculer le hash SHA-256 du fichier
   * Chiffrer le fichier avec AES
   * Suivre le protocole en trois phases pour envoyer le fichier

---

## Choix réalisés dans le projet

* **Utilisateurs** : deux utilisateurs sont pré-configurés pour le test :

  * **alice** : peut se connecter et envoyer des fichiers
  * **bob** : peut se connecter et envoyer des fichiers

* **Client interactif** : au lieu de passer les paramètres en ligne de commande, l’utilisateur les saisit au lancement du client.

* **Fichiers** : le serveur sauvegarde les fichiers reçus dans le dossier `received/`.

* **Cryptographie** :

  * Algorithme AES avec clé pré-partagée entre client et serveur
  * Vérification d’intégrité via SHA-256

---

## Organisation du code

* `SecureFileServer.java` : serveur principal
* `SecureFileClient.java` : client interactif
* `CryptoUtils.java` : fonctions utilitaires pour chiffrement AES et hash SHA-256
* `test.txt` : exemple de fichier à transférer

---

## Fonctionnement

1. Le serveur démarre et écoute un port défini (ex: 5000).
2. L’utilisateur lance le client et saisit :

   * IP du serveur
   * Port
   * Login / mot de passe
   * Chemin du fichier à envoyer
3. Le client calcule le SHA-256, chiffre le fichier et envoie les informations au serveur.
4. Le serveur déchiffre le fichier, vérifie le hash et renvoie `TRANSFER_SUCCESS` si tout est correct.

---

## Résultat

* **Test réussi** avec l’utilisateur `alice` :

  * Le serveur a reçu le fichier chiffré, l’a déchiffré et vérifié l’intégrité
  * Le fichier apparaît dans `received/test.txt`
  * Le client affiche `TRANSFER_SUCCESS`

* Le projet est **fonctionnel et interactif**, prêt pour des tests avec d’autres fichiers ou utilisateurs.

---

## Note

* Le projet peut être amélioré en ajoutant :

  * Gestion automatique du dossier `received`
  * Logs détaillés et horodatés côté serveur
  * Saisie masquée du mot de passe côté client
  * Possibilité de réessayer l’authentification


Ce projet répond aux exigences de l’exercice et illustre un **transfert de fichiers sécurisé en Java** avec chiffrement et vérification d’intégrité.
