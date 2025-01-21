/// Error classes.

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

class AskarError implements Exception {
  final AskarErrorCode code;
  final String message;
  final String? extra;

  AskarError(this.code, this.message, [this.extra]);

  @override
  String toString() {
    var errorInfo = 'AskarError(code: ${code.name}, message: $message';
    if (extra != null) {
      errorInfo += ', extra: $extra';
    }
    return '$errorInfo)';
  }
}
