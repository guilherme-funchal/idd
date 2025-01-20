import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
import '../lib/src/askar_bindings.dart';

void callback(int cbId, int err, int handle) {
  print('Callback chamado com cbId: $cbId, err: $err, handle: $handle');
}

ffi.Pointer<ffi.Char> stringToPointerChar(String input) {
  // Converte a string para um Uint8List contendo os valores ASCII
  final List<int> units = input.codeUnits;

  // Adiciona um byte nulo (\0) no final para representar o término da string
  final List<int> nullTerminatedUnits = [...units, 0];

  // Aloca memória suficiente para armazenar todos os caracteres
  final ffi.Pointer<ffi.Char> pointer =
      malloc.allocate<ffi.Char>(nullTerminatedUnits.length);

  // Copia cada caractere da lista para a memória alocada
  for (int i = 0; i < nullTerminatedUnits.length; i++) {
    pointer.elementAt(i).value = nullTerminatedUnits[i];
  }

  return pointer;
}

void main() {
  // Carregar o código Rust compilado (ajuste o caminho conforme necessário)
  final rustLibrary = new askar_bindings(
      ffi.DynamicLibrary.open('/usr/local/lib/libaries_askar.so'));
  // Altere para o caminho correto

  // Prepare os parâmetros para a função `askar_store_provision`
  final String uri = 'sqlite://storage.db';
  final String keyMethod = 'raw'; // Exemplo de método de chave
  final String passKey = 'mySecretKey';
  final String profile = 'rekey';
  final int recreate = 1; // true como 1, false como 0

  // Converter Strings para UTF-8 (para passar para FFI)
  final uriPtr = stringToPointerChar(uri);
  final keyMethodPtr = stringToPointerChar(keyMethod);
  final passKeyPtr = stringToPointerChar(passKey);
  final profilePtr = stringToPointerChar(profile);

  // Criar ponteiro para o callback
  final ffi.Pointer<
          ffi.NativeFunction<ffi.Void Function(ffi.Int64, ffi.Int64, ffi.Size)>>
      callbackPointer = ffi.Pointer.fromFunction(callback);

  // Chamar a função `askar_store_provision`
  final result = rustLibrary.askar_store_provision(
    uriPtr,
    keyMethodPtr,
    passKeyPtr,
    profilePtr,
    recreate,
    callbackPointer,
    111, // Valor de cbId
  );

  print('Resultado da função askar_store_provision: $result');

  // Libere a memória alocada para as strings após o uso
  // Liberar memória alocada
  calloc.free(uriPtr);
  calloc.free(keyMethodPtr);
  calloc.free(passKeyPtr);
  calloc.free(profilePtr);
}
