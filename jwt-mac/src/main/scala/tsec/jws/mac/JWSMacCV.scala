package tsec.jws.mac

import cats.MonadError
import cats.effect.Sync
import cats.implicits._
import tsec.common._
import tsec.jws._
import tsec.mac.core.{MAC, MacPrograms, MacTag}
import tsec.mac.imports._
import java.time.Instant

import tsec.jwt.JWTClaims

/** Our JWS Compressor, Signer and verifier (CV = Compressor and Verifier)
  *
  * @param hs our header serializer
  * @param programs our mac program implementation
  * @param M Monad instance for F
  * @tparam F Our effect type
  * @tparam A The mac signing algorithm
  */
sealed abstract class JWSMacCV[F[_], A](
    implicit hs: JWSSerializer[JWSMacHeader[A]],
    programs: MacPrograms[F, A, MacSigningKey],
    M: MonadError[F, Throwable]
) {

  /**  Generic Error. Any mishandling of the errors could leak information to an attacker. */
  private def defaultError: MacError = MacVerificationError("Could not verify signature")

  def sign(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[MAC[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key)
  }

  def signAndBuild(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[JWTMac[A]] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key).map(s => JWTMac.buildToken[A](header, body, s))
  }

  def signToString(header: JWSMacHeader[A], body: JWTClaims, key: MacSigningKey[A]): F[String] = {
    val toSign: String = hs.toB64URL(header) + "." + JWTClaims.toB64URL(body)
    programs.sign(toSign.asciiBytes, key).map(s => toSign + "." + s.toB64UrlString)
  }

  def verify(jwt: String, key: MacSigningKey[A], now: Instant): F[Boolean] = {
    val split: Array[String] = jwt.split("\\.", 3)
    if (split.length < 3)
      M.pure(false)
    else {
      val providedBytes: Array[Byte] = split(2).base64UrlBytes
      JWTClaims.fromUtf8Bytes(split(1).base64UrlBytes)
      .fold(
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

  def verifyAndParse(jwt: String, key: MacSigningKey[A], now: Instant): F[JWTMac[A]] = {
    val split = jwt.split("\\.", 3)
    if (split.length != 3)
      M.raiseError(defaultError)
    else {
      val signedBytes: Array[Byte] = split(2).base64UrlBytes
      for {
        header <- M.fromEither(hs.fromUtf8Bytes(split(0).base64UrlBytes).left.map(_ => defaultError))
        claims <- M.fromEither(JWTClaims.fromB64URL(split(1)).left.map(_ => defaultError))
        bytes <- M.ensure(programs.sign((split(0) + "." + split(1)).asciiBytes, key))(defaultError)(
          signed =>
            ByteUtils.constantTimeEquals(signed, signedBytes)
              && claims.isNotExpired(now)
              && claims.isAfterNBF(now)
              && claims.isValidIssued(now)
        )
      } yield JWTMac.buildToken[A](header, claims, bytes)
    }
  }

  def toEncodedString(jwt: JWTMac[A]): String =
    hs.toB64URL(jwt.header) + "." + JWTClaims.toB64URL(jwt.body) + "." + jwt.signature.toB64UrlString
}

object JWSMacCV {

  implicit def genSigner[F[_]: Sync, A: MacTag](
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      alg: JCAMac[F, A],
  ): JWSMacCV[F, A] =
    new JWSMacCV[F, A]() {}

  implicit def genSignerEither[A: MacTag](
      implicit hs: JWSSerializer[JWSMacHeader[A]],
      alg: JCAMacImpure[A]
  ): JWSMacCV[MacErrorM, A] =
    new JWSMacCV[MacErrorM, A]() {}

}
