# Test FFI

## Instalar DART
<pre>
apt update
apt install -y apt-transport-https
wget -qO- https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor > /usr/share/keyrings/dart.gpg
echo "deb [signed-by=/usr/share/keyrings/dart.gpg] https://storage.googleapis.com/download.dartlang.org/linux/debian stable main" > /etc/apt/sources.list.d/dart_stable.list
apt update
apt install dart
export PATH="$PATH:/usr/lib/dart/bin"
source ~/.bashrc
</pre>
  
## Atualiza Libs
#dart pub get

## Executa criar banco
dart run aries_askar/store.dart

## Executa teste Open e Close
dart run aries_askar/store_provision_open_close.dart
