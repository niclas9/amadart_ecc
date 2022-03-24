import '../lib/amadart_ecc.dart';
import 'package:test/test.dart';

void main() {
  group('AMA Key tests', () {
    test('Construct AMA public key from string', () {
      AMAPublicKey publicKey = AMAPublicKey.fromString(
          'AMA8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj');
      print(publicKey);

      expect('AMA8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj',
          publicKey.toString());
    });

    test('Construct AMA public key from string PUB_K1 format', () {
      AMAPublicKey publicKey = AMAPublicKey.fromString(
          'PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX');
      print(publicKey);
    });

    test('Construct AMA private key from string', () {
      // common private key
      AMAPrivateKey privateKey = AMAPrivateKey.fromString(
          '5J9b3xMkbvcT6gYv2EpQ8FD4ZBjgypuNKwE1jxkd7Wd1DYzhk88');
      expect('AMA8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj',
          privateKey.toAMAPublicKey().toString());
      expect('5J9b3xMkbvcT6gYv2EpQ8FD4ZBjgypuNKwE1jxkd7Wd1DYzhk88',
          privateKey.toString());
    });

    test('Invalid AMA private key', () {
      try {
        AMAPrivateKey.fromString(
            '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm');
        fail('Should be invalid private key');
      } on InvalidKey {} catch (e) {
        fail('Should throw InvalidKey exception');
      }
    });

    test('Construct random AMA private key from seed', () {
      AMAPrivateKey privateKey = AMAPrivateKey.fromSeed('abc');
      print(privateKey);
      print(privateKey.toAMAPublicKey());

      AMAPrivateKey privateKey2 =
          AMAPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toAMAPublicKey().toString(),
          privateKey2.toAMAPublicKey().toString());
    });

    test('Construct random AMA private key', () {
      AMAPrivateKey privateKey = AMAPrivateKey.fromRandom();

      print(privateKey);
      print(privateKey.toAMAPublicKey());

      AMAPrivateKey privateKey2 =
          AMAPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toAMAPublicKey().toString(),
          privateKey2.toAMAPublicKey().toString());
    });

    test('Construct AMA private key from string in PVT format', () {
      // PVT private key
      AMAPrivateKey privateKey2 = AMAPrivateKey.fromString(
          'PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd');
      print(privateKey2);
    });

    test('Construct AMA private key from string with compress flag', () {
      // Compressed private key
      AMAPrivateKey privateKey3 = AMAPrivateKey.fromString(
          'L5TCkLizyYqjvKSy6jg1XM3Lc4uTDwwvHS2BYatyXSyoS8T5kC2z');
      print(privateKey3);
    });
  });
}
