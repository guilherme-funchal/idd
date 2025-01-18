import 'dart:ffi';
import 'package:ffi/ffi.dart';

// Carregar a biblioteca compartilhada diretamente
final DynamicLibrary askarLib = DynamicLibrary.open('/usr/local/lib/libaries_askar.so');

// Definição de tipos de funções nativas (função provision)
typedef ProvisionC = Int32 Function(Pointer<Utf8> uri, Pointer<Utf8> keyMethod, Pointer<Utf8> passKey, Pointer<Utf8> profile, Int32 recreate);
typedef ProvisionDart = int Function(Pointer<Utf8> uri, Pointer<Utf8> keyMethod, Pointer<Utf8> passKey, Pointer<Utf8> profile, int recreate);

void main() {
  // Carregar a função "provision" da biblioteca nativa
  final ProvisionDart provision = askarLib
      .lookupFunction<ProvisionC, ProvisionDart>('askar_store_provision');

  // Dados para passar para a função
  final String uri = 'sqlite://storage.db';
  final String keyMethod = 'raw'; // Exemplo de método de chave
  final String passKey = 'mySecretKey';
  final String profile = 'rekey';
  final int recreate = 1; // true como 1, false como 0

  // Converter Strings para UTF-8 (para passar para FFI)
  final uriPtr = uri.toNativeUtf8();
  final keyMethodPtr = keyMethod.toNativeUtf8();
  final passKeyPtr = passKey.toNativeUtf8();
  final profilePtr = profile.toNativeUtf8();

  // Chamar a função provision
  final result = provision(uriPtr, keyMethodPtr, passKeyPtr, profilePtr, recreate);

  print("Resultado da chamada provision: $result");

  // Liberar memória alocada
  calloc.free(uriPtr);
  calloc.free(keyMethodPtr);
  calloc.free(passKeyPtr);
  calloc.free(profilePtr);
}