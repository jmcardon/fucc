package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.effect.IO
import org.http4s.{Request, RequestCookie}
import tsec.keygen.symmetric.IdKeyGen
import tsec.mac.MessageAuth
import tsec.mac.jca._

import scala.concurrent.duration._

class SignedCookieAuthenticatorTests extends RequestAuthenticatorSpec {

  private val cookieName             = "hi"
  implicit def cookieBackingStore[A]: BackingStore[IO, UUID, AuthenticatedCookie[A, Int]] = 
    dummyBackingStore[IO, UUID, AuthenticatedCookie[A, Int]](_.id)

  def genAuthenticator[A](
      implicit keyGenerator: IdKeyGen[A, MacSigningKey],
      store: BackingStore[IO, UUID, AuthenticatedCookie[A, Int]],
      M: MessageAuth[IO, A, MacSigningKey]
  ): AuthSpecTester[AuthenticatedCookie[A, Int]] = {
    val dummyStore = dummyBackingStore[IO, Int, DummyUser](_.id)
    val authenticator = SignedCookieAuthenticator[IO, Int, DummyUser, A](
      TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
      store,
      dummyStore,
      keyGenerator.generateKey
    )
    new AuthSpecTester[AuthenticatedCookie[A, Int]](authenticator, dummyStore) {

      def embedInRequest(request: Request[IO], authenticator: AuthenticatedCookie[A, Int]): Request[IO] = {
        val cookie = authenticator.toCookie
        request.addCookie(RequestCookie(cookie.name, cookie.content))
      }

      def expireAuthenticator(b: AuthenticatedCookie[A, Int]): IO[AuthenticatedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](expiry = now.minusSeconds(2000))
        store.update(updated).map(_ => updated)
      }

      def timeoutAuthenticator(b: AuthenticatedCookie[A, Int]): IO[AuthenticatedCookie[A, Int]] = {
        val now     = Instant.now()
        val updated = b.copy[A, Int](lastTouched = Some(now.minusSeconds(2000)))
        store.update(updated).map(_ => updated)
      }

      def wrongKeyAuthenticator: IO[AuthenticatedCookie[A, Int]] =
        SignedCookieAuthenticator[IO, Int, DummyUser, A](
          TSecCookieSettings(cookieName, false, expiryDuration = 10.minutes, maxIdle = Some(10.minutes)),
          store,
          dummyStore,
          keyGenerator.generateKey
        ).create(123)
    }
  }

  def CookieAuthTest[A](string: String, auth: AuthSpecTester[AuthenticatedCookie[A, Int]]) =
    AuthenticatorTest[AuthenticatedCookie[A, Int]](string, auth)

  def CookieReqTest[A](string: String, auth: AuthSpecTester[AuthenticatedCookie[A, Int]]) =
    requestAuthTests[AuthenticatedCookie[A, Int]](string, auth)

  CookieAuthTest[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])
  CookieAuthTest[HMACSHA256]("HMACSHA256 Authenticator", genAuthenticator[HMACSHA256])
  CookieAuthTest[HMACSHA384]("HMACSHA384 Authenticator", genAuthenticator[HMACSHA384])
  CookieAuthTest[HMACSHA512]("HMACSHA512 Authenticator", genAuthenticator[HMACSHA512])

  CookieReqTest[HMACSHA1]("HMACSHA1 Authenticator", genAuthenticator[HMACSHA1])
  CookieReqTest[HMACSHA256]("HMACSHA256 Authenticator", genAuthenticator[HMACSHA256])
  CookieReqTest[HMACSHA384]("HMACSHA384 Authenticator", genAuthenticator[HMACSHA384])
  CookieReqTest[HMACSHA512]("HMACSHA512 Authenticator", genAuthenticator[HMACSHA512])

  def signedCookieTests[A](
      auth: AuthSpecTester[AuthenticatedCookie[A, Int]]
  )(implicit M: MessageAuth[IO, A, MacSigningKey]) = {

    behavior of "Signed Cookie Authenticator " + M.algorithm

    it should "expire tokens on discard" in {

      val program: IO[Boolean] = for {
        cookie  <- auth.auth.create(0)
        expired <- auth.auth.discard(cookie)
        now     <- IO(Instant.now())
      } yield SignedCookieAuthenticator.isExpired(expired, now, None)

      program.unsafeRunSync() mustBe false

    }

  }

  signedCookieTests[HMACSHA1](genAuthenticator[HMACSHA1])
  signedCookieTests[HMACSHA256](genAuthenticator[HMACSHA256])
  signedCookieTests[HMACSHA384](genAuthenticator[HMACSHA384])
  signedCookieTests[HMACSHA512](genAuthenticator[HMACSHA512])

}
