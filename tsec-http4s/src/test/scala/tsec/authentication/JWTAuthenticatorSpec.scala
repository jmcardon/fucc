package tsec.authentication

import java.time.Instant

import cats.effect.IO
import cats.syntax.all._
import org.http4s.{Header, Request, RequestCookie, SameSite}
import tsec.common.SecureRandomId
import tsec.jws.mac.{JWSMacCV, JWTMac}
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.keygen.symmetric.IdKeyGen
import tsec.mac.jca._

import scala.concurrent.duration._

class JWTAuthenticatorSpec extends RequestAuthenticatorSpec {

  val generalSettings =
    TSecJWTSettings(
      "hi",
      10.minutes,
      Some(10.minutes)
    )

  val generalNoRollSettings =
    TSecJWTSettings(
      "hi",
      10.minutes,
      None
    )

  val generalCookieSettings =
    TSecCookieSettings(
      "hi",
      false,
      false,
      None,
      None,
      SameSite.Lax.some,
      None,
      10.minutes,
      Some(10.minutes)
    )

  val generalNoRollCookieSettings =
    TSecCookieSettings(
      "hi",
      false,
      false,
      None,
      None,
      SameSite.Lax.some,
      None,
      10.minutes,
      None
    )

  implicit def backingStore2[A]: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]] =
    dummyBackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]](s => SecureRandomId.coerce(s.id))

  type BackedAuth[A] =
    (
        BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]],
        IdentityStore[IO, Int, DummyUser],
        MacSigningKey[A]
    ) => JWTAuthenticator[IO, Int, DummyUser, A]

  type UnBackedAuth[A] =
    (IdentityStore[IO, Int, DummyUser], MacSigningKey[A]) => JWTAuthenticator[IO, Int, DummyUser, A]

  type StatelessAuth[A] =
    MacSigningKey[A] => JWTAuthenticator[IO, DummyUser, DummyUser, A]

  type Embedder[A]          = (Request[IO], AugmentedJWT[A, Int]) => Request[IO]
  type StatelessEmbedder[A] = (Request[IO], AugmentedJWT[A, DummyUser]) => Request[IO]

  private[tsec] def embedInBearerToken[I, A: JWTMacAlgo](r: Request[IO], a: AugmentedJWT[A, I])(
      implicit cv: JWSMacCV[IO, A]
  ) = r.putHeaders(buildBearerAuthHeader(JWTMac.toEncodedString(a.jwt)))

  private[tsec] def embedInHeader[I, A: JWTMacAlgo](headerName: String)(r: Request[IO], a: AugmentedJWT[A, I])(
      implicit cv: JWSMacCV[IO, A]
  ): Request[IO] = r.putHeaders(headerName -> JWTMac.toEncodedString(a.jwt))

  private[tsec] def embedInCookie[I, A: JWTMacAlgo](
      settings: TSecCookieSettings
  )(r: Request[IO], a: AugmentedJWT[A, I])(
      implicit cv: JWSMacCV[IO, A]
  ): Request[IO] = {
    val cookie = a.toCookie[IO](settings)
    r.addCookie(RequestCookie(cookie.name, cookie.content))
  }

  /** Stateful tests using Authorization: Header
    *
    */
  def stateful[A: JWTMacAlgo](tf: BackedAuth[A], embedder: Embedder[A])(
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey],
      store: BackingStore[IO, SecureRandomId, AugmentedJWT[A, Int]]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey     = macKeyGen.generateKey
    val authenticator: JWTAuthenticator[IO, Int, DummyUser, A] =
      tf(store, dummyStore, macKey)

    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        embedder(request, authenticator)

      def expireAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] =
        for {
          newToken <- JWTMac
            .build[IO, A](
              b.jwt.body.withExpiry(Instant.now().minusSeconds(10000)),
              macKey
            )

          expired <- store.update(b.copy(jwt = newToken, expiry = Instant.now().minusSeconds(10000)))
        } yield expired

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val newInternal = b.copy(lastTouched = Some(Instant.now().minusSeconds(10000)))
        store.update(newInternal)
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, Int]] =
        tf(store, dummyStore, macKeyGen.generateKey).create(123)
    }
  }

  /** Unencrypted stateless in bearer tests
    *
    */
  def partialStateless[A: JWTMacAlgo](tf: UnBackedAuth[A], embedder: Embedder[A])(
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ): AuthSpecTester[AugmentedJWT[A, Int]] = {
    val dummyStore    = dummyBackingStore[IO, Int, DummyUser](_.id)
    val macKey        = macKeyGen.generateKey
    val authenticator = tf(dummyStore, macKey)

    new AuthSpecTester[AugmentedJWT[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, Int]): Request[IO] =
        embedder(request, authenticator)

      def expireAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- JWTMac
            .build[IO, A](b.jwt.body.withExpiry(expiredInstant), macKey)

        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, Int]): IO[AugmentedJWT[A, Int]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- JWTMac.build[IO, A](b.jwt.body.withIAT(expiredInstant), macKey)
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, Int]] =
        tf(dummyStore, macKey).create(123)
    }
  }

  /** Unencrypted stateless in bearer tests
    *
    */
  def stateless[A: JWTMacAlgo](tf: StatelessAuth[A], embedder: StatelessEmbedder[A])(
      implicit cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ): StatelessSpecTester[AugmentedJWT[A, DummyUser]] = {
    val macKey        = macKeyGen.generateKey
    val authenticator = tf(macKey)

    new StatelessSpecTester[AugmentedJWT[A, DummyUser]](authenticator) {

      def embedInRequest(request: Request[IO], authenticator: AugmentedJWT[A, DummyUser]): Request[IO] =
        embedder(request, authenticator)

      def expireAuthenticator(b: AugmentedJWT[A, DummyUser]): IO[AugmentedJWT[A, DummyUser]] = {
        val expiredInstant = Instant.now().minusSeconds(10000)
        for {
          newToken <- JWTMac
            .build[IO, A](b.jwt.body.withExpiry(expiredInstant), macKey)

        } yield b.copy(jwt = newToken, expiry = expiredInstant)
      }

      def timeoutAuthenticator(b: AugmentedJWT[A, DummyUser]): IO[AugmentedJWT[A, DummyUser]] = {
        val expiredInstant = Instant.now().minusSeconds(20000)
        for {
          newToken <- JWTMac.build[IO, A](b.jwt.body.withIAT(expiredInstant), macKey)
        } yield b.copy(jwt = newToken, lastTouched = Some(expiredInstant))
      }

      def wrongKeyAuthenticator: IO[AugmentedJWT[A, DummyUser]] =
        tf(macKeyGen.generateKey).create(DummyUser(-456))
    }
  }

}
