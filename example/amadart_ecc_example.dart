import 'package:amadart_ecc/amadart_ecc.dart';

main() {
  // Construct the AMA private key from string
  AMAPrivateKey privateKey = AMAPrivateKey.fromString(
      '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3');

  // Get the related AMA public key
  AMAPublicKey publicKey = privateKey.toAMAPublicKey();
  // Print the AMA public key
  print(publicKey.toString());

  // Going to sign the data
  String data = 'data';

  // Sign
  AMASignature signature = privateKey.signString(data);
  // Print the AMA signature
  print(signature.toString());

  // Recover the AMAPublicKey used to sign the data
  var recoveredAMAPublicKey = signature.recover(data);
  print(recoveredAMAPublicKey.toString());

  // Verify the data using the signature
  signature.verify(data, publicKey);
}
