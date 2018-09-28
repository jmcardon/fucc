package tsec.signature

import cats.Functor
import tsec.common.VerificationStatus

trait SignatureAPI[A, PubK[_], PrivK[_]] {

  def sign[F[_]](
      unsigned: Array[Byte],
      secretKey: PrivK[A]
  )(implicit S: Signer[F, A, PubK, PrivK]): F[CryptoSignature[A]] =
    S.sign(unsigned, secretKey)

  def verify[F[_]: Functor](
      raw: Array[Byte],
      signature: CryptoSignature[A],
      publicKey: PubK[A]
  )(implicit S: Signer[F, A, PubK, PrivK]): F[VerificationStatus] =
    S.verify(raw, signature, publicKey)

  def verifyBool[F[_]](
      raw: Array[Byte],
      signature: CryptoSignature[A],
      publicKey: PubK[A]
  )(implicit S: Signer[F, A, PubK, PrivK]): F[Boolean] =
    S.verifyBool(raw, signature, publicKey)

}

trait CertSignatureAPI[A, PubK[_], PrivK[_], Cert[_]] extends SignatureAPI[A, PubK, PrivK] {

  def verifyCert[F[_]](
      raw: Array[Byte],
      signature: CryptoSignature[A],
      publicKey: Cert[A]
  )(implicit S: CertificateSigner[F, A, PubK, PrivK, Cert]): F[Boolean] =
    S.verifyCert(raw, signature, publicKey)

}
