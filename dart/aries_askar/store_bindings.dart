import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
import '../lib/src/askar_bindings.dart';

// Função callback estática necessária pelo FFI
void nativeCallback(int cbId, int err, int handle) {
  //print('Callback chamado com cbId: $cbId, err: $err, handle: $handle');
}

// Criar ponteiro para a função callback
  final callbackPointer = ffi.Pointer.fromFunction<
      ffi.Void Function(ffi.Int64, ffi.Int64, ffi.Size)>(
    nativeCallback,
  );

// Função para converter string em Pointer<Char>
ffi.Pointer<ffi.Char> stringToPointerChar(String input) {
  final units = input.codeUnits;
  final nullTerminatedUnits = [...units, 0];
  final pointer = malloc.allocate<ffi.Char>(nullTerminatedUnits.length);
  for (int i = 0; i < nullTerminatedUnits.length; i++) {
    pointer.elementAt(i).value = nullTerminatedUnits[i];
  }
  return pointer;
}

void main() {
  // Carregar a biblioteca Rust compilada
  final rustLibrary = askar_bindings(
    ffi.DynamicLibrary.open('/usr/local/lib/libaries_askar.so'),
  );

  // Parâmetros
  final uri = 'sqlite://storage.db';
  final keyMethod = 'raw';
  final passKey = 'mySecretKey';
  final profile = 'rekey';
  final recreate = 1;

  // Converter strings para ponteiros
  final uriPtr = stringToPointerChar(uri);
  final keyMethodPtr = stringToPointerChar(keyMethod);
  final passKeyPtr = stringToPointerChar(passKey);
  final profilePtr = stringToPointerChar(profile);

  try {
    // Chamar a função Rust
    final result = rustLibrary.askar_store_provision(
      uriPtr,
      keyMethodPtr,
      passKeyPtr,
      profilePtr,
      recreate,
      callbackPointer.cast(),
      111, // cbId
    );

    print('Resultado da função askar_store_provision: $result');
  } catch (e) {
    print('Erro ao chamar askar_store_provision: $e');
  } finally {
    // Liberar memória
    malloc.free(uriPtr);
    malloc.free(keyMethodPtr);
    malloc.free(passKeyPtr);
    malloc.free(profilePtr);
  }
}
