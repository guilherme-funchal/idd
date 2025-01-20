import 'dart:ffi';
import 'package:ffi/ffi.dart';

// Carregar a biblioteca compartilhada diretamente
final DynamicLibrary askarLib =
    DynamicLibrary.open('/usr/local/lib/libaries_askar.so');

// Definição de tipos de funções nativas (função provision)
typedef ProvisionC = Int32 Function(Pointer<Utf8> uri, Pointer<Utf8> keyMethod,
    Pointer<Utf8> passKey, Pointer<Utf8> profile, Int32 recreate);
typedef ProvisionDart = int Function(Pointer<Utf8> uri, Pointer<Utf8> keyMethod,
    Pointer<Utf8> passKey, Pointer<Utf8> profile, int recreate);

// Definição de tipos de funções nativas (função open)
typedef OpenC = Int32 Function(
    Pointer<Utf8> uri, Pointer<Utf8> profile, Pointer<Utf8> key);
typedef OpenDart = int Function(
    Pointer<Utf8> uri, Pointer<Utf8> profile, Pointer<Utf8> key);

// Definição de tipos de funções nativas (função close)
typedef CloseC = Int32 Function(Int32 remove);
typedef CloseDart = int Function(int remove);

// Enum para códigos de erro
enum AskarErrorCode {
  SUCCESS(0),
  BACKEND(1),
  BUSY(2),
  DUPLICATE(3),
  ENCRYPTION(4),
  INPUT(5),
  NOT_FOUND(6),
  UNEXPECTED(7),
  UNSUPPORTED(8),
  WRAPPER(99),
  CUSTOM(100);

  final int value;

  const AskarErrorCode(this.value);

  static AskarErrorCode fromValue(int value) {
    return AskarErrorCode.values.firstWhere(
      (code) => code.value == value,
      orElse: () => AskarErrorCode.UNEXPECTED,
    );
  }
}

// Classe para representar erros do Askar
class AskarError implements Exception {
  final AskarErrorCode code;
  final String message;
  final String? extra;

  AskarError(this.code, this.message, [this.extra]);

  @override
  String toString() {
    var errorInfo =
        'AskarError(code: ${code.name}, codeValue: ${code.value}, message: $message';
    if (extra != null) {
      errorInfo += ', extra: $extra';
    }
    return '$errorInfo)';
  }
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
void provisionStore(DynamicLibrary askarLib, String uri, String keyMethod,
    String passKey, String profile, int recreate) {
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
void openStore(
    DynamicLibrary askarLib, String uri, String keyMethod, String key) {
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
void closeStore(DynamicLibrary askarLib, int remove) {
  final CloseDart close =
      askarLib.lookupFunction<CloseC, CloseDart>('askar_store_close');

  // Chamar a função close
  final result = close(remove);

  // Verificar e tratar o código de erro
  checkError(result, 'askar_store_close');
  print("Store fechado com sucesso. Código de retorno: $result");
}

void main() {
  // Carregar a biblioteca compartilhada
  final DynamicLibrary askarLib =
      DynamicLibrary.open('/usr/local/lib/libaries_askar.so');

  // Parâmetros para provisionar o store
  final String uri = 'sqlite://storage.db';
  final String keyMethod = 'raw';
  final String passKey = 'mySecretKey';
  final String profile = 'rekey';
  final int recreate = 1; // 1 para recriar, 0 para manter

  try {
    // Provisionar o store
    provisionStore(askarLib, uri, keyMethod, passKey, profile, recreate);
    Future.delayed(Duration(seconds: 5));

    // Abrir o store
    openStore(askarLib, uri, keyMethod, passKey);

    // Aqui você pode realizar operações com o store
  } on AskarError catch (e) {
    print("Erro capturado: $e");
  } finally {
    // Fechar o store
    try {
      closeStore(askarLib, 1); // 0 = não remove os dados do store
    } on AskarError catch (e) {
      print("Erro ao fechar o store: $e");
    }
  }
}

