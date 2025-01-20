import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
import '../lib/aries_askar_ffi.dart';

void main() async {
  final ariesAskar = AriesAskarFFI(
    ffi.DynamicLibrary.open('/usr/local/lib/libaries_askar.so'),
  );

  try {
    final handle = await ariesAskar.askarStoreProvision(
      'sqlite://storage.db',
      'raw',
      'mySecretKey',
      'rekey',
      1,
    );

    print('Handle retornado: $handle');
  } catch (e) {
    print('Erro: $e');
  }
}