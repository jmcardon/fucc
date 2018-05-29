package tsec.authentication

import java.time.Instant

import cats.data.OptionT
import cats.effect.Sync
import cats.instances.string._
import cats.syntax.all._
import io.circe.{Decoder, Encoder, ObjectEncoder}
import org.http4s.util.CaseInsensitiveString
import org.http4s.{Cookie, Header, HttpDate, Request, Response}
import tsec.authentication.internal._
import tsec.common._
import tsec.jws.mac._
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.keyrotation.{KeyStrategy, StaticKeyStrategy}
import tsec.mac.jca.{JCAMacTag, MacSigningKey}

import scala.concurrent.duration.FiniteDuration

/**
  * Note: Not sealed in case of user-defined
  * custom behavior
  */
abstract class JWTAuthenticator[F[_]: Sync, I, V, A] extends Authenticator[F, I, V, AugmentedJWT[A, I]]

/** An `Authenticator` that wraps a JWTMAC[A]
  *
  */
final case class AugmentedJWT[A, I](
    id: SecureRandomId,
    jwt: JWTMac[A],
    identity: I,
    expiry: Instant,
    lastTouched: Option[Instant]
) {
  def toCookie[F[_]](settings: TSecCookieSettings)(implicit F: Sync[F], J: JWSMacCV[F, A], algo: JWTMacAlgo[A]) =
    Cookie(
      settings.cookieName,
      JWTMac.toEncodedString[F, A](jwt),
      expires = Some(HttpDate.unsafeFromInstant(expiry)),
      None,
      settings.domain,
      settings.path,
      settings.secure,
      settings.httpOnly,
      settings.extension
    )

}

object AugmentedJWT {
  implicit def auth[A, I]: AuthToken[AugmentedJWT[A, I]] = new AuthToken[AugmentedJWT[A, I]] {
    def expiry(a: AugmentedJWT[A, I]): Instant = a.expiry

    def lastTouched(a: AugmentedJWT[A, I]): Option[Instant] = a.lastTouched
  }
}

object JWTAuthenticator {

  /** Create a JWT Authenticator that will transport it as a
    * bearer token
    */
  private[tsec] def backingStore[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
      identityStore: IdentityStore[F, I, V],
      keyStrat: KeyStrategy[F, MacSigningKey, A],
      extract: Request[F] => Option[String],
      embedInResponse: (Response[F], AugmentedJWT[A, I]) => Response[F]
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
    maxIdle match {
      case Some(maxIdleTime) =>
        new StatefulJWTAuth[F, I, V, A](expiryDuration, maxIdle, tokenStore, identityStore, keyStrat) {

          private def verifyWithRaw(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            JWTMac.toEncodedString(retrieved.jwt) === raw && !retrieved.isExpired(now) &&
              !retrieved.isTimedOut(now, maxIdleTime)

          private[tsec] def verifyAndRefresh(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            if (verifyWithRaw(raw, retrieved, now))
              refresh(retrieved)
            else
              F.raiseError(AuthenticationFailure)

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            F.delay(Instant.now()).flatMap { now =>
              tokenStore.update(authenticator.copy(lastTouched = Some(now)))
            }

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            embedInResponse(response, authenticator)
        }

      case None =>
        new StatefulJWTAuth[F, I, V, A](expiryDuration, maxIdle, tokenStore, identityStore, keyStrat) {

          /** A conditional to check for:
            * 1. Token serialization equality. No need to verify the signature, this is done via our
            * jwt deserializer
            *
            * @param raw
            * @param retrieved
            * @return
            */
          private def verifyWithRaw(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            JWTMac.toEncodedString(retrieved.jwt) === raw && !retrieved.isExpired(now)

          private[tsec] def verifyAndRefresh(raw: String, retrieved: AugmentedJWT[A, I], now: Instant) =
            if (verifyWithRaw(raw, retrieved, now))
              F.pure(retrieved)
            else
              F.raiseError(AuthenticationFailure)

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            F.pure(authenticator)

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            embedInResponse(response, authenticator)
        }
    }

  private[tsec] def partialStateless[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
      expiry: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      identityStore: IdentityStore[F, I, V],
      keyStrategy: KeyStrategy[F, MacSigningKey, A],
      extract: Request[F] => Option[String],
      embedInResponse: (Response[F], AugmentedJWT[A, I]) => Response[F]
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
    maxIdle match {
      case Some(mIdle) =>
        new PartialStatelessJWTAuth[F, I, V, A](expiry, maxIdle, identityStore, keyStrategy) {

          private[tsec] def verifyLastTouched(body: JWTMac[A], now: Instant): F[Option[Instant]] =
            for {
              iat <- F.delay(body.body.issuedAt)
              instant <- if (!iat.exists(_.plusSeconds(mIdle.toSeconds).isBefore(now)))
                F.pure(iat)
              else
                F.raiseError(AuthenticationFailure)
            } yield instant

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            for {
              now      <- F.delay(Instant.now())
              key      <- keyStrategy.retrieveKey
              newToken <- JWTMac.build(authenticator.jwt.body.withIAT(now), key)
            } yield authenticator.copy(jwt = newToken, lastTouched = Some(now))

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            embedInResponse(response, authenticator)

          def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
            OptionT.pure[F](embed(response, authenticator))
        }

      case None =>
        new PartialStatelessJWTAuth[F, I, V, A](expiry, maxIdle, identityStore, keyStrategy) {

          private[tsec] def verifyLastTouched(body: JWTMac[A], now: Instant): F[Option[Instant]] =
            F.pure(None)

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, I]): F[AugmentedJWT[A, I]] =
            F.pure(authenticator)

          def embed(response: Response[F], authenticator: AugmentedJWT[A, I]): Response[F] =
            embedInResponse(response, authenticator)

          def afterBlock(response: Response[F], authenticator: AugmentedJWT[A, I]): OptionT[F, Response[F]] =
            OptionT.pure[F](response)
        }
    }

  private[tsec] def embedded[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo: JCAMacTag](
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration],
      keyStrategy: KeyStrategy[F, MacSigningKey, A],
      extract: Request[F] => Option[String],
      embedInResponse: (Response[F], AugmentedJWT[A, V]) => Response[F]
  )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, V, V, A] =
    maxIdle match {
      case Some(mIdle) =>
        new StatelessJWTAuth[F, V, A](expiryDuration, maxIdle, keyStrategy) {
          private[tsec] def verifyLastTouched(body: JWTMac[A], now: Instant) =
            for {
              iat <- F.delay(body.body.issuedAt)
              instant <- if (!iat.exists(_.plusSeconds(mIdle.toSeconds).isBefore(now)))
                F.pure(iat)
              else
                F.raiseError(AuthenticationFailure)
            } yield instant

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, V]): F[AugmentedJWT[A, V]] =
            for {
              now      <- F.delay(Instant.now())
              key      <- keyStrategy.retrieveKey
              newToken <- JWTMac.build(authenticator.jwt.body.withIAT(now), key)
            } yield authenticator.copy(jwt = newToken, lastTouched = Some(now))

          def embed(response: Response[F], authenticator: AugmentedJWT[A, V]): Response[F] =
            embedInResponse(response, authenticator)

        }

      case None =>
        new StatelessJWTAuth[F, V, A](expiryDuration, maxIdle, keyStrategy) {

          private[tsec] def verifyLastTouched(body: JWTMac[A], now: Instant) = F.pure(None)

          def extractRawOption(request: Request[F]): Option[String] =
            extract(request)

          def refresh(authenticator: AugmentedJWT[A, V]): F[AugmentedJWT[A, V]] =
            F.pure(authenticator)

          def embed(response: Response[F], authenticator: AugmentedJWT[A, V]): Response[F] =
            embedInResponse(response, authenticator)
        }
    }

  private[tsec] def embedInBearerToken[F[_], I, A: JWTMacAlgo](r: Response[F], a: AugmentedJWT[A, I])(
      implicit cv: JWSMacCV[F, A],
      F: Sync[F]
  ) = r.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(a.jwt)))

  private[tsec] def extractFromHeader[F[_]](headerName: String)(r: Request[F]): Option[String] =
    r.headers.get(CaseInsensitiveString(headerName)).map(_.value)

  private[tsec] def embedInHeader[F[_], I, A: JWTMacAlgo](headerName: String)(r: Response[F], a: AugmentedJWT[A, I])(
      implicit cv: JWSMacCV[F, A],
      F: Sync[F]
  ): Response[F] = r.putHeaders(Header(headerName, JWTMac.toEncodedString(a.jwt)))

  private[tsec] def extractFromCookie[F[_]](cookieName: String)(r: Request[F]): Option[String] =
    unliftedCookieFromRequest[F](cookieName, r).map(_.content)

  private[tsec] def embedInCookie[F[_], I, A: JWTMacAlgo](
      settings: TSecCookieSettings
  )(r: Response[F], a: AugmentedJWT[A, I])(
      implicit cv: JWSMacCV[F, A],
      F: Sync[F]
  ): Response[F] = r.addCookie(a.toCookie[F](settings))

  object backed {

    /** Create a JWT Authenticator that will transport it as a
      * bearer token
      */
    def inBearerToken[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
        expiryDuration: FiniteDuration,
        maxIdle: Option[FiniteDuration],
        tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
        identityStore: IdentityStore[F, I, V],
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      backingStore[F, I, V, A](
        expiryDuration,
        maxIdle,
        tokenStore,
        identityStore,
        StaticKeyStrategy[F](signingKey),
        extractBearerToken[F],
        embedInBearerToken[F, I, A]
      )

    /** Create a JWT Authenticator that will transport it as a
      * bearer token
      */
    def inBearerToken[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
        expiryDuration: FiniteDuration,
        maxIdle: Option[FiniteDuration],
        tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
        identityStore: IdentityStore[F, I, V],
        signingKey: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      backingStore[F, I, V, A](
        expiryDuration,
        maxIdle,
        tokenStore,
        identityStore,
        signingKey,
        extractBearerToken[F],
        embedInBearerToken[F, I, A]
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inHeader[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecJWTSettings,
        tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
        identityStore: IdentityStore[F, I, V],
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      backingStore[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        tokenStore,
        identityStore,
        StaticKeyStrategy[F](signingKey),
        extractFromHeader[F](settings.headerName),
        embedInHeader[F, I, A](settings.headerName)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inHeader[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecJWTSettings,
        tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
        identityStore: IdentityStore[F, I, V],
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      backingStore[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        tokenStore,
        identityStore,
        keyStrategy,
        extractFromHeader[F](settings.headerName),
        embedInHeader[F, I, A](settings.headerName)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inCookie[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecCookieSettings,
        tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
        identityStore: IdentityStore[F, I, V],
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      backingStore[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        tokenStore,
        identityStore,
        StaticKeyStrategy[F](signingKey),
        extractFromCookie[F](settings.cookieName),
        embedInCookie[F, I, A](settings)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inCookie[F[_], I, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecCookieSettings,
        tokenStore: BackingStore[F, SecureRandomId, AugmentedJWT[A, I]],
        identityStore: IdentityStore[F, I, V],
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      backingStore[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        tokenStore,
        identityStore,
        keyStrategy,
        extractFromCookie[F](settings.cookieName),
        embedInCookie[F, I, A](settings)
      )
  }

  object unbacked {

    /** Create a JWT Authenticator that will transport it as a
      * bearer token
      */
    def inBearerToken[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
        expiryDuration: FiniteDuration,
        maxIdle: Option[FiniteDuration],
        identityStore: IdentityStore[F, I, V],
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      partialStateless[F, I, V, A](
        expiryDuration,
        maxIdle,
        identityStore,
        StaticKeyStrategy[F](signingKey),
        extractBearerToken[F],
        embedInBearerToken[F, I, A]
      )

    /** Create a JWT Authenticator that will transport it as a
      * bearer token
      */
    def inBearerToken[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
        expiryDuration: FiniteDuration,
        maxIdle: Option[FiniteDuration],
        identityStore: IdentityStore[F, I, V],
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      partialStateless[F, I, V, A](
        expiryDuration,
        maxIdle,
        identityStore,
        keyStrategy,
        extractBearerToken[F],
        embedInBearerToken[F, I, A]
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inHeader[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecJWTSettings,
        identityStore: IdentityStore[F, I, V],
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      partialStateless[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        identityStore,
        StaticKeyStrategy[F](signingKey),
        extractFromHeader[F](settings.headerName),
        embedInHeader[F, I, A](settings.headerName)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inHeader[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecJWTSettings,
        identityStore: IdentityStore[F, I, V],
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      partialStateless[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        identityStore,
        keyStrategy,
        extractFromHeader[F](settings.headerName),
        embedInHeader[F, I, A](settings.headerName)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inCookie[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecCookieSettings,
        identityStore: IdentityStore[F, I, V],
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      partialStateless[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        identityStore,
        StaticKeyStrategy[F](signingKey),
        extractFromCookie[F](settings.cookieName),
        embedInCookie[F, I, A](settings)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inCookie[F[_], I: Decoder: Encoder, V, A: JWTMacAlgo: JCAMacTag](
        settings: TSecCookieSettings,
        identityStore: IdentityStore[F, I, V],
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, I, V, A] =
      partialStateless[F, I, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        identityStore,
        keyStrategy,
        extractFromCookie[F](settings.cookieName),
        embedInCookie[F, I, A](settings)
      )
  }

  object pstateless {

    /** Create a JWT Authenticator that will transport it as a
      * bearer token
      */
    def inBearerToken[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo: JCAMacTag](
        expiryDuration: FiniteDuration,
        maxIdle: Option[FiniteDuration],
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, V, V, A] =
      embedded[F, V, A](
        expiryDuration,
        maxIdle,
        StaticKeyStrategy[F](signingKey),
        extractBearerToken[F],
        embedInBearerToken[F, V, A]
      )

    /** Create a JWT Authenticator that will transport it as a
      * bearer token
      */
    def inBearerToken[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo: JCAMacTag](
        expiryDuration: FiniteDuration,
        maxIdle: Option[FiniteDuration],
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, V, V, A] =
      embedded[F, V, A](
        expiryDuration,
        maxIdle,
        keyStrategy,
        extractBearerToken[F],
        embedInBearerToken[F, V, A]
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inHeader[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo: JCAMacTag](
        settings: TSecJWTSettings,
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, V, V, A] =
      embedded[F, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        StaticKeyStrategy[F](signingKey),
        extractFromHeader[F](settings.headerName),
        embedInHeader[F, V, A](settings.headerName)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inHeader[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo: JCAMacTag](
        settings: TSecJWTSettings,
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, V, V, A] =
      embedded[F, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        keyStrategy,
        extractFromHeader[F](settings.headerName),
        embedInHeader[F, V, A](settings.headerName)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inCookie[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo: JCAMacTag](
        settings: TSecCookieSettings,
        signingKey: MacSigningKey[A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, V, V, A] =
      embedded[F, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        StaticKeyStrategy[F](signingKey),
        extractFromCookie[F](settings.cookieName),
        embedInCookie[F, V, A](settings)
      )

    /** Create a JWT Authenticator that will transport it in
      * an arbitrary header, with a backing store.
      *
      */
    def inCookie[F[_], V: Decoder: ObjectEncoder, A: JWTMacAlgo: JCAMacTag](
        settings: TSecCookieSettings,
        keyStrategy: KeyStrategy[F, MacSigningKey, A]
    )(implicit cv: JWSMacCV[F, A], F: Sync[F]): JWTAuthenticator[F, V, V, A] =
      embedded[F, V, A](
        settings.expiryDuration,
        settings.maxIdle,
        keyStrategy,
        extractFromCookie[F](settings.cookieName),
        embedInCookie[F, V, A](settings)
      )
  }

}
