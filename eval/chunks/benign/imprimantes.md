# Imprimantes du siège

## Ajouter une imprimante
Ouvrir **Paramètres > Imprimantes** et choisir `\\print.acme.fr\ETAGE3-COULEUR`.

## Problèmes fréquents
- *Bourrage papier* : suivre le guide affiché sur l'écran de l'imprimante.
- *File d'attente bloquée* :

```cmd
net stop spooler
net start spooler
```

Indiquez à l'utilisateur de redémarrer le poste si le pilote ne se réinstalle pas.
