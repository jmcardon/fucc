package tsec.authentication

import cats.effect.IO
import io.circe.generic.auto._
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials}
import tsec.jws.mac.{JWSMacCV, JWTMac}
import tsec.jwt.JWTClaims
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.keygen.symmetric.IdKeyGen
import tsec.mac.MessageAuth
import tsec.mac.jca._

class JWTAuthenticatorTests extends JWTAuthenticatorSpec {

  case class JWTTestingGroup[A, B](authenticator: A, embedder: B, title: String)

  /** backed **/
  def runStatefulAuthenticators[A: JWTMacAlgo](
      implicit M: MessageAuth[IO, A, MacSigningKey],
      cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ) =
    List[JWTTestingGroup[BackedAuth[A], Embedder[A]]](
      JWTTestingGroup(
        JWTAuthenticator.backed.inBearerToken[IO, Int, DummyUser, A](
          generalSettings.expiryDuration,
          generalSettings.maxIdle,
          _,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inCookie[IO, Int, DummyUser, A](
          generalCookieSettings,
          _,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inHeader[IO, Int, DummyUser, A](
          generalSettings,
          _,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inBearerToken[IO, Int, DummyUser, A](
          generalNoRollSettings.expiryDuration,
          generalNoRollSettings.maxIdle,
          _,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inCookie[IO, Int, DummyUser, A](
          generalNoRollCookieSettings,
          _,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.backed.inHeader[IO, Int, DummyUser, A](
          generalNoRollSettings,
          _,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header rolling"
      )
    ).foreach {
      case t =>
        AuthenticatorTest[AugmentedJWT[A, Int]](
          s"Authenticator Stateful spec: ${t.title}",
          stateful[A](t.authenticator, t.embedder)
        )
        requestAuthTests[AugmentedJWT[A, Int]](
          s"Request Auth Stateful spec: ${t.title}",
          stateful[A](t.authenticator, t.embedder)
        )
    }

  /** backed **/
  def runPartialStatelessAuthenticators[A: JWTMacAlgo](
      implicit M: MessageAuth[IO, A, MacSigningKey],
      cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ) =
    List[JWTTestingGroup[UnBackedAuth[A], Embedder[A]]](
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inBearerToken[IO, Int, DummyUser, A](
          generalSettings.expiryDuration,
          generalSettings.maxIdle,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inCookie[IO, Int, DummyUser, A](
          generalCookieSettings,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inHeader[IO, Int, DummyUser, A](
          generalSettings,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inBearerToken[IO, Int, DummyUser, A](
          generalNoRollSettings.expiryDuration,
          generalNoRollSettings.maxIdle,
          _,
          _
        ),
        embedInBearerToken[Int, A],
        s"${M.algorithm} in bearer token rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inCookie[IO, Int, DummyUser, A](
          generalNoRollCookieSettings,
          _,
          _
        ),
        embedInCookie[Int, A](generalCookieSettings),
        s"${M.algorithm} in cookie rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.unbacked.inHeader[IO, Int, DummyUser, A](
          generalNoRollSettings,
          _,
          _
        ),
        embedInHeader[Int, A](generalSettings.headerName),
        s"${M.algorithm} in header rolling"
      )
    ).foreach {
      case t =>
        AuthenticatorTest[AugmentedJWT[A, Int]](
          s"Authenticator Partial Stateless spec: ${t.title}",
          partialStateless[A](t.authenticator, t.embedder)
        )
        requestAuthTests[AugmentedJWT[A, Int]](
          s"Request Auth Partial Stateless spec: ${t.title}",
          partialStateless[A](t.authenticator, t.embedder)
        )
    }

  /** backed **/
  def runStatelessAuthenticators[A: JWTMacAlgo](
      implicit M: MessageAuth[IO, A, MacSigningKey],
      cv: JWSMacCV[IO, A],
      macKeyGen: IdKeyGen[A, MacSigningKey]
  ) =
    List[JWTTestingGroup[StatelessAuth[A], StatelessEmbedder[A]]](
      JWTTestingGroup(
        JWTAuthenticator.pstateless.inBearerToken[IO, DummyUser, A](
          generalSettings.expiryDuration,
          generalSettings.maxIdle,
          _
        ),
        embedInBearerToken[DummyUser, A],
        s"${M.algorithm} in bearer token no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.pstateless.inCookie[IO, DummyUser, A](
          generalCookieSettings,
          _
        ),
        embedInCookie[DummyUser, A](generalCookieSettings),
        s"${M.algorithm} in cookie no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.pstateless.inHeader[IO, DummyUser, A](
          generalSettings,
          _
        ),
        embedInHeader[DummyUser, A](generalSettings.headerName),
        s"${M.algorithm} in header no rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.pstateless.inBearerToken[IO, DummyUser, A](
          generalNoRollSettings.expiryDuration,
          generalNoRollSettings.maxIdle,
          _
        ),
        embedInBearerToken[DummyUser, A],
        s"${M.algorithm} in bearer token rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.pstateless.inCookie[IO, DummyUser, A](
          generalNoRollCookieSettings,
          _
        ),
        embedInCookie[DummyUser, A](generalCookieSettings),
        s"${M.algorithm} in cookie rolling"
      ),
      JWTTestingGroup(
        JWTAuthenticator.pstateless.inHeader[IO, DummyUser, A](
          generalNoRollSettings,
          _
        ),
        embedInHeader[DummyUser, A](generalSettings.headerName),
        s"${M.algorithm} in header rolling"
      )
    ).foreach { t =>
      StatelessAuthenticatorTest[AugmentedJWT[A, DummyUser]](
        s"Authenticator Stateless spec: ${t.title}",
        stateless[A](t.authenticator, t.embedder)
      )
      statelessReqAuthTests[AugmentedJWT[A, DummyUser]](
        s"Request Auth Stateless spec: ${t.title}",
        stateless[A](t.authenticator, t.embedder)
      )
    }

  /** End Stateless Encrypted Auth Bearer Header Tests **/
  def checkAuthHeader[A: JWTMacAlgo](
      implicit M: MessageAuth[IO, A, MacSigningKey],
      cv: JWSMacCV[IO, A],
      macKeyGen: MacKeyGen[IO, A]
  ) = {
    behavior of M.algorithm + " JWT Token64 check"
    macKeyGen.generateKey
      .map { key =>
        it should "pass token68 check" in {
          forAll { (testSubject: String) =>
            val token = "Bearer "

            val (rawToken, parsed) = JWTMac
              .buildToString(JWTClaims(subject = Some(testSubject)), key)
              .map(s => (s, Authorization.parse(token + s)))
              .unsafeRunSync()

            parsed mustBe Right(Authorization(Credentials.Token(AuthScheme.Bearer, rawToken)))
          }

        }
      }
      .unsafeRunSync()
  }

  checkAuthHeader[HMACSHA256]
  checkAuthHeader[HMACSHA384]
  checkAuthHeader[HMACSHA512]
  runStatefulAuthenticators[HMACSHA256]
  runStatefulAuthenticators[HMACSHA384]
  runStatefulAuthenticators[HMACSHA512]
  runPartialStatelessAuthenticators[HMACSHA256]
  runPartialStatelessAuthenticators[HMACSHA384]
  runPartialStatelessAuthenticators[HMACSHA512]
  runStatelessAuthenticators[HMACSHA256]
  runStatelessAuthenticators[HMACSHA384]
  runStatelessAuthenticators[HMACSHA512]

}
