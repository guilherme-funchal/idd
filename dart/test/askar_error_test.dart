import 'package:test/test.dart';
import '../aries_askar/error.dart'; // Substitua pelo caminho real do arquivo.

void main() {
  group('AskarError tests', () {
    test('Deve criar um AskarError com código SUCCESS', () {
      final error = AskarError(AskarErrorCode.SUCCESS, 'Operação bem-sucedida');

      // Imprime os resultados
      print('Código do erro: ${error.code}');
      print('Mensagem: ${error.message}');
      print('Extra: ${error.extra}');
      print('ToString: ${error.toString()}');

      expect(error.code, equals(AskarErrorCode.SUCCESS));
      expect(error.message, equals('Operação bem-sucedida'));
      expect(error.extra, isNull);
      expect(error.toString(), contains('AskarError(code: SUCCESS, message: Operação bem-sucedida'));
    });

    test('Deve criar um AskarError com código CUSTOM e mensagem extra', () {
      final error = AskarError(
        AskarErrorCode.CUSTOM,
        'Erro personalizado',
        'Detalhes extras',
      );

      // Imprime os resultados
      print('Código do erro: ${error.code}');
      print('Mensagem: ${error.message}');
      print('Extra: ${error.extra}');
      print('ToString: ${error.toString()}');

      expect(error.code, equals(AskarErrorCode.CUSTOM));
      expect(error.message, equals('Erro personalizado'));
      expect(error.extra, equals('Detalhes extras'));
      expect(error.toString(), contains('extra: Detalhes extras'));
    });

    test('Deve capturar o erro em um bloco try-catch', () {
      try {
        throw AskarError(
          AskarErrorCode.NOT_FOUND,
          'Recurso não encontrado',
        );
      } catch (e) {
        // Imprime o erro capturado
        print('Erro capturado: $e');

        expect(e, isA<AskarError>());
        final askarError = e as AskarError;
        expect(askarError.code, equals(AskarErrorCode.NOT_FOUND));
        expect(askarError.message, equals('Recurso não encontrado'));
      }
    });

    test('Deve testar diferentes códigos de erro', () {
      for (var code in AskarErrorCode.values) {
        final error = AskarError(
          code,
          'Mensagem para $code',
        );

        // Imprime os resultados
        print('Testando código: $code');
        print('Mensagem: ${error.message}');

        expect(error.code, equals(code));
        expect(error.message, equals('Mensagem para $code'));
      }
    });
  });
}
