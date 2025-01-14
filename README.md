# Elliptic curve cryptography (ECC) in Dart

Elliptic curve cryptography lib for AMAX based blockchain in Dart lang.

## Usage

A simple usage example:

```dart
import 'package:amaxdart_ecc/amaxdart_ecc.dart';

main() {
  // Construct the AMAX private key from string
  AMAXPrivateKey privateKey = AMAXPrivateKey.fromString(
      '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3');

  // Get the related AMAX public key
  AMAXPublicKey publicKey = privateKey.toAMAXPublicKey();
  // Print the AMAX public key
  print(publicKey.toString());

  // Going to sign the data
  String data = 'data';

  // Sign
  AMAXSignature signature = privateKey.signString(data);
  // Print the AMAX signature
  print(signature.toString());

  // Verify the data using the signature
  signature.verify(data, publicKey);
}
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

## References

eosjs-ecc: https://github.com/EOSIO/eosjs-ecc

[tracker]: https://github.com/niclas9/amaxdart_ecc/issues
