#!/bin/sh
# Creates the Google Play upload key and tells the Android build where it is.
# Run it yourself: keytool asks for the passwords, and they stay on this machine.
set -e
# Everything this writes is a secret: owner-only from the moment it exists,
# not after a chmod.
umask 077
cd "$(dirname "$0")/.."
JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
DIR="$HOME/.nap-release"; KEY="$DIR/nap-upload.jks"
mkdir -p "$DIR"; chmod 700 "$DIR"
[ -e "$KEY" ] && { echo "$KEY already exists; not overwriting it."; exit 1; }
"$JAVA_HOME/bin/keytool" -genkeypair -v -keystore "$KEY" -alias upload -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=Nap Wallet"
chmod 600 "$KEY"
printf "Keystore password again (for the build): "; stty -echo; read PW; stty echo; echo
cat > src-tauri/gen/android/keystore.properties <<PROPS
storeFile=$KEY
storePassword=$PW
keyAlias=upload
keyPassword=$PW
PROPS
chmod 600 src-tauri/gen/android/keystore.properties
echo "Upload key: $KEY — back it up somewhere safe. keystore.properties written (not committed)."
