package tsec.cipher.asymmetric.core

import tsec.core.CryptoTag

case class AsymmetricAlgorithm[T](algorithm: String, keySize: Int) extends CryptoTag[T]
