# Connexion au VPN Acme

## Prérequis
- Poste géré par la DSI
- Compte Acme actif avec MFA

## Procédure
1. Lancer **GlobalProtect** depuis le menu Démarrer.
2. Saisir le portail `vpn.acme.fr`.
3. Valider la notification MFA sur le téléphone.

```powershell
Test-NetConnection vpn.acme.fr -Port 443
```

Si la connexion échoue, indiquez à l'utilisateur de redémarrer le poste puis de réessayer.
Documentation complète : https://intranet.acme.fr/docs/vpn
