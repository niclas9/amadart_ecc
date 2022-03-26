import '../lib/amaxdart_ecc.dart';
import 'package:test/test.dart';

void main() {
  group('AMAX Key tests', () {
    test('Construct AMAX public key from string', () {
      AMAXPublicKey publicKey = AMAXPublicKey.fromString('AM8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj');
      print(publicKey);

      expect('AM8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj', publicKey.toString());
    });

    test('Construct AMAX public key from string PUB_K1 format', () {
      AMAXPublicKey publicKey = AMAXPublicKey.fromString('PUB_K1_859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2Ht7beeX');
      print(publicKey);
    });

    test('Construct AMAX private key from string', () {
      // common private key
      AMAXPrivateKey privateKey = AMAXPrivateKey.fromString('5J9b3xMkbvcT6gYv2EpQ8FD4ZBjgypuNKwE1jxkd7Wd1DYzhk88');
      expect('AM8Qi58kbERkTJC7A4gabxYU4SbrAxStJHacoke4sf6AvJyEDZXj', privateKey.toAMAXPublicKey().toString());
      expect('5J9b3xMkbvcT6gYv2EpQ8FD4ZBjgypuNKwE1jxkd7Wd1DYzhk88', privateKey.toString());
    });

    test('Invalid AMAX private key', () {
      try {
        AMAXPrivateKey.fromString('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjsm');
        fail('Should be invalid private key');
      } on InvalidKey {
      } catch (e) {
        fail('Should throw InvalidKey exception');
      }
    });

    test('Construct random AMAX private key from seed', () {
      AMAXPrivateKey privateKey = AMAXPrivateKey.fromSeed('abc');
      print(privateKey);
      print(privateKey.toAMAXPublicKey());

      AMAXPrivateKey privateKey2 = AMAXPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toAMAXPublicKey().toString(), privateKey2.toAMAXPublicKey().toString());
    });

    test('Construct random AMAX private key', () {
      AMAXPrivateKey privateKey = AMAXPrivateKey.fromRandom();

      print(privateKey);
      print(privateKey.toAMAXPublicKey());

      AMAXPrivateKey privateKey2 = AMAXPrivateKey.fromString(privateKey.toString());
      expect(privateKey.toAMAXPublicKey().toString(), privateKey2.toAMAXPublicKey().toString());
    });

    test('Construct AMAX private key from string in PVT format', () {
      // PVT private key
      AMAXPrivateKey privateKey2 =
          AMAXPrivateKey.fromString('PVT_K1_2jH3nnhxhR3zPUcsKaWWZC9ZmZAnKm3GAnFD1xynGJE1Znuvjd');
      print(privateKey2);
    });

    test('Construct AMAX private key from string with compress flag', () {
      // Compressed private key
      AMAXPrivateKey privateKey3 = AMAXPrivateKey.fromString('L5TCkLizyYqjvKSy6jg1XM3Lc4uTDwwvHS2BYatyXSyoS8T5kC2z');
      print(privateKey3);
    });
  });
}
