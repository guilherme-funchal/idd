import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'error.dart';
import 'type_def.dart';

class AskarBridge {
  // Carregar a biblioteca compartilhada diretamente
  final DynamicLibrary askarLib;
  final String uri;
  final String keyMethod;
  final String passKey;
  final String profile;
  final int recreate;

  AskarBridge(
      {required this.askarLib,
      required this.uri,
      required this.keyMethod,
      required this.passKey,
      required this.profile,
      required this.recreate});

  Future storeProvision() async {
    final ProvisionDart provision = askarLib
        .lookupFunction<ProvisionC, ProvisionDart>('askar_store_provision');

    // true como 1, false como 0

    // Converter Strings para UTF-8 (para passar para FFI)
    final uriPtr = uri.toNativeUtf8();
    final keyMethodPtr = keyMethod.toNativeUtf8();
    final passKeyPtr = passKey.toNativeUtf8();
    final profilePtr = profile.toNativeUtf8();

    // Chamar a função provision
    final result =
        provision(uriPtr, keyMethodPtr, passKeyPtr, profilePtr, recreate);

    print("Resultado da chamada provision: $result");

    // Liberar memória alocada
    calloc.free(uriPtr);
    calloc.free(keyMethodPtr);
    calloc.free(passKeyPtr);
    calloc.free(profilePtr);
  }

  // Função para verificar o código de erro e lançar exceção, se necessário
  void checkError(int resultCode, String functionName) {
    if (resultCode != AskarErrorCode.SUCCESS.value) {
      final errorCode = AskarErrorCode.fromValue(resultCode);
      throw AskarError(
        errorCode,
        'Erro na função $functionName',
        'Código de erro: $resultCode',
      );
    }
  }

// Função para provisionar o store
  void provisionStore() {
    final ProvisionDart provision = askarLib
        .lookupFunction<ProvisionC, ProvisionDart>('askar_store_provision');

    // Converter Strings para UTF-8
    final uriPtr = uri.toNativeUtf8();
    final keyMethodPtr = keyMethod.toNativeUtf8();
    final passKeyPtr = passKey.toNativeUtf8();
    final profilePtr = profile.toNativeUtf8();

    try {
      // Chamar a função provision
      final result =
          provision(uriPtr, keyMethodPtr, passKeyPtr, profilePtr, recreate);

      // Verificar e tratar o código de erro
      checkError(result, 'askar_store_provision');
      print("Store provisionado com sucesso. Código de retorno: $result");
    } finally {
      // Liberar memória alocada
      calloc.free(uriPtr);
      calloc.free(keyMethodPtr);
      calloc.free(passKeyPtr);
      calloc.free(profilePtr);
    }
  }

// Função para abrir o store
  void openStore(String key) {
    final OpenDart open =
        askarLib.lookupFunction<OpenC, OpenDart>('askar_store_open');

    // Converter Strings para UTF-8
    final uriPtr = uri.toNativeUtf8();
    final keyMethodPtr = keyMethod.toNativeUtf8();
    final keyPtr = key.toNativeUtf8();

    try {
      // Chamar a função open
      final result = open(uriPtr, keyMethodPtr, keyPtr);

      // Verificar e tratar o código de erro
      checkError(result, 'askar_store_open');
      print("Store aberto com sucesso. Código de retorno: $result");
    } finally {
      // Liberar memória alocada
      calloc.free(uriPtr);
      calloc.free(keyMethodPtr);
      calloc.free(keyPtr);
    }
  }

// Função para fechar o store
  void closeStore(int remove) {
    final CloseDart close =
        askarLib.lookupFunction<CloseC, CloseDart>('askar_store_close');

    // Chamar a função close
    final result = close(remove);

    // Verificar e tratar o código de erro
    checkError(result, 'askar_store_close');
    print("Store fechado com sucesso. Código de retorno: $result");
  }
}
