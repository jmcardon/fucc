package tsec.jws.mac

import cats.{Monad, MonadError}
import cats.effect.{Effect, IO}
import cats.implicits._
import tsec.core.ByteUtils
import tsec.core.ByteUtils._
import tsec.jws._
import tsec.jwt.claims.JWTClaims
import tsec.mac.core.MacPrograms
import tsec.mac.instance._
import java.time.Instant

/**
  * Our JWS Compressor, Signer and verifier (CV = Compressor and Verifier)
  *
  * @param hs our header serializer
  * @param programs our mac program implementation
  * @param aux Case class shape
  * @param M Monad instance for F
  * @tparam F Our effect type
  * @tparam A The mac signing algorithm
  */
sealed abstract class JWSMacCV[F[_], A](
    implicit hs: JWSSerializer[JWSMacHeader[A]],
    programs: MacPrograms[F, A, MacSigningKey],
    aux: ByteAux[A],
    M: MonadError[F, MacError]
) {

  /*
  Generic Error.
  Any mishandling of the errors could leak information to an attacker.
   */
  private def defaultError: MacError = MacVerificationError("Could not verify signature")

  def sign(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[JWSSignature[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key).map(s => JWSSignature(s))
  }

  def signAndBuild(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[JWTMac[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key).map(s => JWTMac.buildToken[A](header, body, JWSSignature(s)))
  }

  def signToString(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[String] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key).map(s => toSign + "." + aux.to(s).head.toB64UrlString)
  }

  def verify(jwt: String, key: MacSigningKey[A]): F[Boolean] = {
    val now: Instant         = Instant.now()
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length < 3)
      M.pure(false)
    else {
      val providedBytes: Array[Byte] = split(2).base64UrlBytes
      (for {
        _      <- hs.fromUtf8Bytes(split(0).base64UrlBytes)
        claims <- JWTClaims.fromUtf8Bytes(split(1).base64UrlBytes)
      } yield claims).fold(
        _ => M.pure(false),
        claims =>
          programs.algebra
            .sign((split(0) + "." + split(1)).asciiBytes, key)
            .map {
              ByteUtils.constantTimeEquals(_, providedBytes) && claims.isNotExpired(now) && claims
                .isAfterNBF(now) && claims.isValidIssued(now)
          }
      )
    }
  }

  def verifyAndParse(jwt: String, key: MacSigningKey[A]): F[JWTMac[A]] = {
    val now   = Instant.now
    val split = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError(defaultError)
    else {
      val signedBytes: Array[Byte] = split(2).base64UrlBytes
      for {
        header <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        claims <- M.fromEither(JWTClaims.fromB64URL(split(1)).left.map(_ => defaultError))
        bytes <- M.ensure(programs.algebra.sign((split(0) + "." + split(1)).asciiBytes, key))(defaultError)(
          signed =>
            ByteUtils.constantTimeEquals(signed, signedBytes)
              && claims.isNotExpired(now)
              && claims.isAfterNBF(now)
              && claims.isValidIssued(now)
        )
      } yield JWTMac.buildToken[A](header, claims, JWSSignature(bytes))
    }
  }

  def toEncodedString(jwt: JWTMac[A]): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.toB64URL(jwt.body) + "." + jwt.signature.body.toB64UrlString
}

object JWSMacCV {
  /*
  This will simply coerce the type narrowing for MonadError. Particularly useful for cats-effect
   */
  private implicit def MonadErrorCoerce[F[_]](implicit M: MonadError[F, Throwable]): MonadError[F, MacError] =
    M.asInstanceOf[MonadError[F, MacError]]

  implicit def genSigner[F[_], A: ByteAux](
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      alg: MacPrograms[F, A, MacSigningKey],
      monadError: MonadError[F, MacError]
  ): JWSMacCV[F, A] =
    new JWSMacCV[F, A]() {}

  implicit def genSignerIO[A: ByteAux](
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      alg: JCAMacPure[A]
  ): JWSMacCV[IO, A] =
    new JWSMacCV[IO, A]() {}

  implicit def genSignerEither[A: ByteAux](
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      alg: JCAMacImpure[A]
  ): JWSMacCV[MacErrorM, A] =
    new JWSMacCV[MacErrorM, A]() {}

}
