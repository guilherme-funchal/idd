import 'dart:async';
import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';

typedef CallbackType = ffi.Void Function(
      ffi.Int32 id, ffi.Int32 errorCode, ffi.Pointer<ffi.Void> response);

class AriesAskarFFI {
  final ffi.DynamicLibrary nativeLibrary;

  AriesAskarFFI(this.nativeLibrary);


  // Função estática que será usada como callback
  static void callback(int id, int errorCode, ffi.Pointer<ffi.Void> response) {
    // Lógica do callback
    if (errorCode != 0) {
      print("Erro no código $errorCode");
      return;
    }

    final responseString = response.cast<Utf8>().toDartString();
    print("Resposta recebida: $responseString");
  }

  Future<T> promisifyWithResponse<T>(
      Function(ffi.Pointer<ffi.NativeFunction<CallbackType>>, int) ffiCall) async {
    final completer = Completer<T>();

    // Criar o callback como ponteiro
    final callbackPointer = ffi.Pointer.fromFunction<CallbackType>(callback);
    print("callback 1");
    print(callbackPointer);
    // Registrar o callback no FFI
    ffiCall(callbackPointer, 123);
    print("callback 2");
    print(callbackPointer);
    // Aqui você retornaria o resultado esperado, utilizando o `completer.future`
    print("chamou promisifyWithResponse");
    return completer.future;
  }

  Future<String> askarStoreProvision(
    String specUri,
    String keyMethod,
    String passKey,
    String profile,
    int recreate,
  ) async {
    final specUriPtr = specUri.toNativeUtf8();
    final keyMethodPtr = keyMethod.toNativeUtf8();
    final passKeyPtr = passKey.toNativeUtf8();
    final profilePtr = profile.toNativeUtf8();

    try {
      return promisifyWithResponse<String>((cb, cbId) {
        print("callback");
        print(cb);
        return nativeLibrary
            .lookupFunction<
                ffi.Int32 Function(
                    ffi.Pointer<Utf8>,
                    ffi.Pointer<Utf8>,
                    ffi.Pointer<Utf8>,
                    ffi.Pointer<Utf8>,
                    ffi.Int32,
                    ffi.Pointer<ffi.NativeFunction<
                        ffi.Void Function(ffi.Int32, ffi.Int32, ffi.Pointer<ffi.Void>)>>,
                    ffi.Int32),
                int Function(
                    ffi.Pointer<Utf8>,
                    ffi.Pointer<Utf8>,
                    ffi.Pointer<Utf8>,
                    ffi.Pointer<Utf8>,
                    int,
                    ffi.Pointer<ffi.NativeFunction<
                        ffi.Void Function(ffi.Int32, ffi.Int32, ffi.Pointer<ffi.Void>)>>,
                    int)>('askar_store_provision')(
          specUriPtr,
          keyMethodPtr,
          passKeyPtr,
          profilePtr,
          recreate,
          cb,
          cbId,
        );
      });
    } finally {
      print('vai liberar a memoria');
      malloc.free(specUriPtr);
      malloc.free(keyMethodPtr);
      malloc.free(passKeyPtr);
      malloc.free(profilePtr);
    }
  }
}
