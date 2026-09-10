# Otapo

Contrôle local de prises et lampes Tapo (protocole KLAP) pour WearOS et Android.

Deux modules, un seul package `com.hn.otapo` (requis pour le Wear Data Layer) :
- `app` : application montre WearOS (pilotage, complications, synchro Data Layer)
- `mobile` : application téléphone Android (pilotage complet, synchro vers la montre)

## Fonctionnalités

- Contrôle local via KLAP avec repli passthrough (ON/OFF, luminosité, couleur, température)
- Appareils supportés : P100, P110, L510, L520, L530, L610, L630, génériques
- Découverte réseau + ajout manuel par IP (nécessite « Compatibilité des appareils tiers » activée dans l'app Tapo officielle)
- Groupes d'appareils (tout ON/OFF, réordonner, édition)
- Synchro téléphone ↔ montre via Wear Data Layer (appareils + compte actif)
- Complications WearOS + tuile Quick Settings + widgets Android
- Énergie (P110, relevé périodique + graphique)
- Minuteries et horaires récurrents, surveillance hors-ligne avec notifications
- Zones GPS (geofencing entrée/sortie), multi-comptes, raccourcis vocaux / App Actions / deep links (`opentapo://`, `https://otapo.hn/toggle`)
- Sauvegarde / restauration JSON chiffrée (phrase secrète)

## Build

Prérequis : Android SDK + JDK 17.

```bash
export ANDROID_HOME=/home/ubuntu/android-sdk
export JAVA_HOME=/home/ubuntu/jdk17
./gradlew :app:assembleDebug :mobile:assembleDebug --no-daemon
```

APK générés dans `app/build/outputs/apk/debug/` et `mobile/build/outputs/apk/debug/`.

## Signature Data Layer

Les deux modules partagent `applicationId com.hn.otapo` et doivent être signés
avec la même clé pour que `DataClient` / `MessageClient` routent entre téléphone
et montre.
