package tsec.csrf

import java.security.MessageDigest
import java.time.Clock

import cats.data.{Kleisli, OptionT}
import cats.effect.Sync
import cats.syntax.all._
import org.http4s.{HttpRoutes, Request, Response, ResponseCookie, Status}
import tsec.authentication.{cookieFromRequest, unliftedCookieFromRequest}
import tsec.common._
import tsec.mac.jca.{JCAMessageAuth, _}
import org.typelevel.ci._

/** Middleware to avoid Cross-site request forgery attacks.
  * More info on CSRF at: https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)
  *
  * This middleware is modeled after the double submit cookie pattern:
  * https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookie
  *
  * When a user authenticates, `embedNew` is used to send a random CSRF value as a cookie.  (Alternatively,
  * an authenticating service can be wrapped in `withNewToken`).
  *
  * For requests that are unsafe (PUT, POST, DELETE, PATCH), services protected by the `validated` method in the
  * middleware will check that the csrf token is present in both the header `headerName` and the cookie `cookieName`.
  * Due to the Same-Origin policy, an attacker will be unable to reproduce this value in a
  * custom header, resulting in a `401 Unauthorized` response.
  *
  * Requests with safe methods (such as GET, OPTIONS, HEAD) will have a new token embedded in them if there isn't one,
  * or will receive a refreshed token based off of the previous token to mitigate the BREACH vulnerability. If a request
  * contains an invalid token, regardless of whether it is a safe method, this middleware will fail it with
  * `401 Unauthorized`. In this situation, your user(s) should clear their cookies for your page, to receive a new
  * token.
  *
  * We'd like to emphasize that you please follow proper design principles in creating endpoints, as to
  * not mutate in what should otherwise be idempotent methods (i.e no dropping your DB in a GET method, or altering
  * user data). If you choose to not to, this middleware cannot protect you.
  *
  *
  * @param headerName your CSRF header name
  * @param cookieName the CSRF cookie name
  * @param key the CSRF signing key
  * @param clock clock used as a nonce
  */
final class TSecCSRF[F[_], A] private[tsec] (
    key: MacSigningKey[A],
    val headerName: String,
    val cookieName: String,
    val tokenLength: Int,
    clock: Clock
)(implicit mac: JCAMessageAuth[F, A], F: Sync[F]) {

  def isEqual(s1: String, s2: String): Boolean =
    MessageDigest.isEqual(s1.utf8Bytes, s2.utf8Bytes)

  def signToken(string: String): F[CSRFToken] =
    for {
      millis <- F.delay(clock.millis())
      joined = string + "-" + millis
      signed <- mac.sign(joined.utf8Bytes, key)
    } yield CSRFToken(joined + "-" + signed.toB64String)

  def generateToken: F[CSRFToken] =
    signToken(CSRFToken.generateHexBase(tokenLength))

  /**
    * Extract a signed token
    */
  def extractRaw(token: CSRFToken): OptionT[F, String] =
    token.split("-", 3) match {
      case Array(raw, nonce, signed) =>
        OptionT(
          mac
            .sign((raw + "-" + nonce).utf8Bytes, key)
            .map(
              f =>
                signed.b64UrlBytes.flatMap { bytes =>
                  if (MessageDigest.isEqual(f, bytes)) Some(raw) else None
              }
            )
        )
      case _ =>
        OptionT.none
    }

  private[tsec] def validateOrEmbed(request: Request[F], service: HttpRoutes[F]): OptionT[F, Response[F]] =
    unliftedCookieFromRequest[F](cookieName, request) match {
      case Some(c) =>
        OptionT.liftF(
          (for {
            raw      <- extractRaw(CSRFToken(c.content))
            response <- service(request)
            newToken <- OptionT.liftF(signToken(raw))
          } yield response.addCookie(ResponseCookie(name = cookieName, content = newToken)))
            .getOrElse(Response[F](Status.Unauthorized))
        )
      case None =>
        service(request).semiflatMap(embedNew)
    }

  private[tsec] def checkCSRF(r: Request[F], service: HttpRoutes[F]): F[Response[F]] =
    (for {
      c1       <- cookieFromRequest[F](cookieName, r)
      c2       <- OptionT.fromOption[F](r.headers.get(CIString(headerName)).map(_.head.value))
      raw1     <- extractRaw(CSRFToken(c1.content))
      raw2     <- extractRaw(CSRFToken(c2))
      res      <- if (isEqual(raw1, raw2)) service(r) else OptionT.none[F, Response[F]]
      newToken <- OptionT.liftF(signToken(raw1)) //Generate a new token to guard against BREACH.
    } yield res.addCookie(ResponseCookie(name = cookieName, content = newToken)))
      .getOrElse(Response[F](Status.Unauthorized))

  def filter(predicate: Request[F] => Boolean, request: Request[F], service: HttpRoutes[F]): OptionT[F, Response[F]] =
    if (predicate(request))
      validateOrEmbed(request, service)
    else
      OptionT.liftF(checkCSRF(request, service))

  def checkEqual(token1: CSRFToken, token2: CSRFToken): OptionT[F, Boolean] =
    for {
      raw1 <- extractRaw(token1)
      raw2 <- extractRaw(token2)
    } yield isEqual(raw1, raw2)

  def validate(predicate: Request[F] => Boolean = _.method.isSafe): CSRFMiddleware[F] =
    req =>
      Kleisli { (r: Request[F]) =>
        filter(predicate, r, req)
    }

  def withNewToken: CSRFMiddleware[F] = _.andThen(r => OptionT.liftF(embedNew(r)))

  def embedNew(response: Response[F]): F[Response[F]] =
    generateToken.map(t => response.addCookie(ResponseCookie(name = cookieName, content = t)))

}

object TSecCSRF {
  def apply[F[_]: Sync, A](
      key: MacSigningKey[A],
      headerName: String = "X-TSec-Csrf",
      cookieName: String = "tsec-csrf",
      tokenLength: Int = 32,
      clock: Clock = Clock.systemUTC()
  )(implicit M: JCAMessageAuth[F, A]): TSecCSRF[F, A] =
    new TSecCSRF[F, A](key, headerName, cookieName, tokenLength, clock)
}
