import 'dart:ffi';
import 'package:ffi/ffi.dart';

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
