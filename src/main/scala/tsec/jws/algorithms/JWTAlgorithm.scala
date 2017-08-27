package tsec.jws.algorithms

import cats.MonadError
import tsec.jws.algorithms.JWTSigAlgo.MErrThrowable
import tsec.jws.signature.ParseEncodedKeySpec
import tsec.mac.instance._
import tsec.mac.core.MacPrograms
import tsec.signature.core.{SignatureAlgorithm, SignerDSL}
import tsec.signature.instance._

sealed trait JWTAlgorithm[A] {
  val jwtRepr: String

}

object JWTAlgorithm {
  implicit case object HS256 extends JWTMacAlgo[HMACSHA256] {
    val jwtRepr: String = "HS256"
  }

  implicit case object HS384 extends JWTMacAlgo[HMACSHA384] {
    val jwtRepr: String = "HS384"
  }

  implicit case object HS512 extends JWTMacAlgo[HMACSHA512] {
    val jwtRepr: String = "HS512"
  }

  implicit case object NoAlg extends JWTAlgorithm[NoSigningAlgorithm] {
    val jwtRepr: String = "none"
  }

  implicit case object ES256 extends JWTECSig[SHA256withECDSA] {
    val jwtRepr: String = "ES256"
  }

  implicit case object ES384 extends JWTECSig[SHA384withECDSA] {
    val jwtRepr: String = "ES384"
  }

  implicit case object ES512 extends JWTECSig[SHA512withECDSA] {
    val jwtRepr: String = "ES512"
  }

  implicit case object RS256 extends JWTRSASig[SHA256withRSA]{
    val jwtRepr: String = "RS256"
  }

  implicit case object RS384 extends JWTRSASig[SHA384withRSA]{
    val jwtRepr: String = "RS384"
  }

  implicit case object RS512 extends JWTRSASig[SHA512withRSA]{
    val jwtRepr: String = "RS512"
  }

}

abstract class JWTMacAlgo[A: MacTag](implicit gen: MacPrograms.MacAux[A]) extends JWTAlgorithm[A]

abstract class JWTSigAlgo[A: SignatureAlgorithm](implicit gen: SignerDSL.Aux[A]) extends JWTAlgorithm[A] {
  def byteReprToJCA[F[_]](bytes: Array[Byte])(implicit me: MErrThrowable[F]): F[Array[Byte]]
  def derBytesToJCA[F[_]](bytes: Array[Byte])(implicit me: MErrThrowable[F]): F[Array[Byte]]
}

abstract class JWTECSig[A: SignatureAlgorithm: ECKFTag](implicit gen: SignerDSL.Aux[A]) extends JWTSigAlgo[A]{
  def byteReprToJCA[F[_]](bytes: Array[Byte])(implicit me: MErrThrowable[F]): F[Array[Byte]] = ParseEncodedKeySpec.concatSignatureToDER[F, A](bytes)
  def derBytesToJCA[F[_]](bytes: Array[Byte])(implicit me: MErrThrowable[F]): F[Array[Byte]] = ParseEncodedKeySpec.derToConcat[F, A](bytes)
}

abstract class JWTRSASig[A: SignatureAlgorithm](implicit gen: SignerDSL.Aux[A]) extends JWTSigAlgo[A]{
  def byteReprToJCA[F[_]](bytes: Array[Byte])(implicit me: MErrThrowable[F]): F[Array[Byte]] = me.pure(bytes)
  def derBytesToJCA[F[_]](bytes: Array[Byte])(implicit me: MErrThrowable[F]): F[Array[Byte]] = me.pure(bytes)
}

object JWTSigAlgo {
  type MErrThrowable[F[_]] = MonadError[F, Throwable]
}

object JWTMacAlgo {


  def fromString[A](alg: String)(implicit o: JWTMacAlgo[A]): Option[JWTMacAlgo[A]] = alg match {
    case o.jwtRepr => Some(o)
    //While we work on signatures, this can be none.
    case _ => None
  }
}
