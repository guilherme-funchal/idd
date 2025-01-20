import 'dart:ffi';
import 'dart:async';
import 'package:ffi/ffi.dart';

// Carregar a biblioteca compartilhada diretamente
final DynamicLibrary askarLib = DynamicLibrary.open('/usr/local/lib/libaries_askar.so');

// Definição de tipos de funções nativas (função provision)
typedef ProvisionC = Int32 Function(Pointer<Utf8> uri, Pointer<Utf8> keyMethod, Pointer<Utf8> passKey, Pointer<Utf8> profile, Int32 recreate);
typedef ProvisionDart = int Function(Pointer<Utf8> uri, Pointer<Utf8> keyMethod, Pointer<Utf8> passKey, Pointer<Utf8> profile, int recreate);

// StreamController para gerenciar canais
final StreamController<Map<String, dynamic>> _channel = StreamController();

void main() async {
  // Assinar para escutar o canal
  _channel.stream.listen((data) async {
    if (data['action'] == 'provision') {
      final result = await provisionAsync(
        uri: data['uri'],
        keyMethod: data['keyMethod'],
        passKey: data['passKey'],
        profile: data['profile'],
        recreate: data['recreate'],
      );
      print("Resultado da chamada provision: $result");
    }
  });

  // Enviar dados para o canal
  _channel.add({
    'action': 'provision',
    'uri': 'sqlite://storage.db',
    'keyMethod': 'raw',
    'passKey': 'mySecretKey',
    'profile': 'rekey',
    'recreate': 1,
  });

  // Fechar o canal ao final
  await Future.delayed(Duration(seconds: 1));
  await _channel.close();
}

// Função assíncrona para execução de provision
Future<int> provisionAsync({
  required String uri,
  required String keyMethod,
  required String passKey,
  required String profile,
  required int recreate,
}) async {
  return await Future(() {
    // Carregar a função "provision" da biblioteca nativa
    final ProvisionDart provision = askarLib
        .lookupFunction<ProvisionC, ProvisionDart>('askar_store_provision');

    // Converter Strings para UTF-8
    final uriPtr = uri.toNativeUtf8();
    final keyMethodPtr = keyMethod.toNativeUtf8();
    final passKeyPtr = passKey.toNativeUtf8();
    final profilePtr = profile.toNativeUtf8();

    try {
      // Chamar a função provision
      final result = provision(uriPtr, keyMethodPtr, passKeyPtr, profilePtr, recreate);
      return result;
    } finally {
      // Liberar memória alocada
      calloc.free(uriPtr);
      calloc.free(keyMethodPtr);
      calloc.free(passKeyPtr);
      calloc.free(profilePtr);
    }
  });
}
