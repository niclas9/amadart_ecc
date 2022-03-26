import 'package:amaxdart_ecc/amaxdart_ecc.dart';

main() {
  // Construct the AMAX private key from string
  AMAXPrivateKey privateKey = AMAXPrivateKey.fromString('5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3');

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

  // Recover the AMAXPublicKey used to sign the data
  var recoveredAMAXPublicKey = signature.recover(data);
  print(recoveredAMAXPublicKey.toString());

  // Verify the data using the signature
  signature.verify(data, publicKey);
}
