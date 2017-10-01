package tsec.signature.instance

import java.security.{PrivateKey, PublicKey, Signature}

import cats.effect.{Async, Sync}
import tsec.signature.core._

sealed abstract class JCASigInterpreter[F[_], A](implicit M: Sync[F], signatureAlgorithm: SigAlgoTag[A])
    extends SignatureAlgebra[F, A] {
  type S     = Signature
  type PubK  = SigPublicKey[A]
  type PrivK = SigPrivateKey[A]
  type Cert  = SigCertificate[A]

  def genSignatureInstance: F[Signature] = M.delay(Signature.getInstance(signatureAlgorithm.algorithm))

  def initSign(instance: Signature, p: SigPrivateKey[A]): F[Unit] = M.delay(instance.initSign(p.key))

  def initVerifyK(instance: Signature, p: SigPublicKey[A]): F[Unit] = M.delay(instance.initVerify(p.key))

  def initVerifyC(instance: Signature, c: SigCertificate[A]): F[Unit] =
    M.delay(instance.initVerify(c.certificate))

  def loadBytes(bytes: Array[Byte], instance: Signature): F[Unit] = M.delay(M.delay(instance.update(bytes)))

  def sign(instance: Signature): F[Array[Byte]] = M.delay(instance.sign())

  def verify(sig: Array[Byte], instance: Signature): F[Boolean] = M.delay(instance.verify(sig))

}

object JCASigInterpreter {

  def apply[F[_]: Sync, A: SigAlgoTag] = new JCASigInterpreter[F, A]() {}

  implicit def genSig[F[_]: Sync, A: SigAlgoTag]: JCASigInterpreter[F, A] = apply[F, A]

}
