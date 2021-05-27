package tsec

import java.time.Instant
import java.util.UUID

import cats.data.{Kleisli, OptionT}
import cats.effect.Sync
import cats.implicits._
import cats.{Applicative, Monad}
import io.circe._
import org.http4s._
import org.http4s.headers.{Authorization, Cookie => C}
import org.http4s.server.Middleware
import tsec.authorization.{Authorization => TAuth}
import tsec.common.TSecError

import scala.concurrent.duration.FiniteDuration

package object authentication {

  trait IdentityStore[F[_], I, V] {

    def get(id: I): OptionT[F, V]

  }

  trait BackingStore[F[_], I, V] extends IdentityStore[F, I, V] {
    def put(elem: V): F[V]

    def update(v: V): F[V]

    def delete(id: I): F[Unit]
  }

  /** Inspired from the Silhouette `SecuredRequest`
    *
    */
  final case class SecuredRequest[F[_], Identity, Auth](request: Request[F], identity: Identity, authenticator: Auth)

  final case class UserAwareRequest[F[_], Identity, Auth](request: Request[F], maybe: Option[(Identity, Auth)])

  object asAuthed {

    /** Matcher for the http4s dsl
      * @param ar
      * @tparam F
      * @tparam A
      * @tparam I
      * @return
      */
    def unapply[F[_], I, A](ar: SecuredRequest[F, I, A]): Option[(Request[F], I)] =
      Some(ar.request -> ar.identity)
  }

  type TSecMiddleware[F[_], I, A] =
    Middleware[({type T[A] = OptionT[F, A]})#T, SecuredRequest[F, I, A], Response[F], Request[F], Response[F]]

  object TSecMiddleware {
    def apply[F[_]: Monad, I, Auth](
        authedStuff: Kleisli[({type T[A] = OptionT[F, A]})#T, Request[F], SecuredRequest[F, I, Auth]],
        onNotAuthenticated: Request[F] => F[Response[F]]
    ): TSecMiddleware[F, I, Auth] =
      service => {
        Kleisli { r: Request[F] =>
          OptionT.liftF(
            authedStuff
              .run(r)
              .flatMap(service.mapF(o => OptionT.liftF(o.getOrElse(Response[F](Status.NotFound)))).run)
              .getOrElseF(onNotAuthenticated(r))
          )
        }
      }

    def withFallthrough[F[_]: Monad, I, Auth](
        authedStuff: Kleisli[({type T[A] = OptionT[F, A]})#T, Request[F], SecuredRequest[F, I, Auth]],
        onNotAuthenticated: Request[F] => F[Response[F]]
    ): TSecMiddleware[F, I, Auth] =
      service => {
        Kleisli { r: Request[F] =>
          authedStuff
            .run(r)
            .flatMap(service.mapF(o => OptionT.liftF(o.getOrElse(Response[F](Status.NotFound)))).run)
        }
      }

  }

  // The parameter types of TSecAuthService are reversed from what
  // we'd expect. This is a workaround to ensure partial unification
  // is triggered.  See https://github.com/jmcardon/tsec/issues/88 for
  // more info.
  type TSecAuthService[I, A, F[_]] = Kleisli[({type T[A] = OptionT[F, A]})#T, SecuredRequest[F, I, A], Response[F]]

  object TSecAuthService {

    /** Lifts a partial function to an `TSecAuthedService`.  Responds with
      * [[org.http4s.Response.notFound]], which generates a 404, for any request
      * where `pf` is not defined.
      */
    def apply[I, A, F[_]](
        pf: PartialFunction[SecuredRequest[F, I, A], F[Response[F]]]
    )(implicit F: Monad[F]): TSecAuthService[I, A, F] =
      Kleisli(req => pf.andThen(OptionT.liftF(_)).applyOrElse(req, Function.const(OptionT.none)))

    def apply[I, A, F[_]](
        pf: PartialFunction[SecuredRequest[F, I, A], F[Response[F]]],
        andThen: (Response[F], A) => OptionT[F, Response[F]]
    )(implicit F: Monad[F]): TSecAuthService[I, A, F] =
      Kleisli(
        req =>
          pf.andThen(OptionT.liftF(_))
            .applyOrElse(req, Function.const(OptionT.none[F, Response[F]]))
            .flatMap(r => andThen(r, req.authenticator))
      )

    def withAuthorizationF[I, A, F[_]](auth: F[TAuth[F, I, A]])(
        pf: PartialFunction[SecuredRequest[F, I, A], F[Response[F]]]
    )(implicit F: Monad[F]): TSecAuthService[I, A, F] =
      withAuthorizationFHandler(auth)(pf, defaultOnNotAuthorized[F, I, A])

    def withAuthorizationFHandler[I, A, F[_]](auth: F[TAuth[F, I, A]])(
        pf: PartialFunction[SecuredRequest[F, I, A], F[Response[F]]],
        onNotAuthorized: SecuredRequest[F, I, A] => OptionT[F, Response[F]]
    )(implicit F: Monad[F]): TSecAuthService[I, A, F] =
      Kleisli { req: SecuredRequest[F, I, A] =>
        OptionT.liftF(auth).flatMap { auth =>
          auth
            .isAuthorized(req)
            .flatMap(_ => pf.andThen(OptionT.liftF(_)).applyOrElse(req, Function.const(OptionT.none[F, Response[F]])))
            .orElse(onNotAuthorized(req))
        }
      }

    def withAuthorization[I, A, F[_]](auth: TAuth[F, I, A])(
        pf: PartialFunction[SecuredRequest[F, I, A], F[Response[F]]]
    )(implicit F: Monad[F]): TSecAuthService[I, A, F] =
      withAuthorizationHandler(auth)(pf, defaultOnNotAuthorized[F, I, A])

    def withAuthorizationHandler[I, A, F[_]](auth: TAuth[F, I, A])(
        pf: PartialFunction[SecuredRequest[F, I, A], F[Response[F]]],
        onNotAuthorized: SecuredRequest[F, I, A] => OptionT[F, Response[F]]
    )(implicit F: Monad[F]): TSecAuthService[I, A, F] =
      Kleisli { req: SecuredRequest[F, I, A] =>
        auth
          .isAuthorized(req)
          .flatMap(_ => pf.andThen(OptionT.liftF(_)).applyOrElse(req, Function.const(OptionT.none[F, Response[F]])))
          .orElse(onNotAuthorized(req))
      }

    /** The empty service (all requests fallthrough).
      * @tparam F - Ignored
      * @tparam I - Ignored
      * @tparam A - Ignored
      * @return
      */
    def empty[A, I, F[_]: Applicative]: TSecAuthService[I, A, F] =
      Kleisli.liftF(OptionT.none)

    def defaultOnNotAuthorized[F[_], I, A](
        unused: SecuredRequest[F, I, A]
    )(implicit F: Monad[F]): OptionT[F, Response[F]] =
      OptionT(F.pure(Some(Response[F](Status.Unauthorized))))
  }

  type UserAwareService[I, A, F[_]] =
    Kleisli[({type T[A] = OptionT[F, A]})#T, UserAwareRequest[F, I, A], Response[F]]

  type UserAwareMiddleware[F[_], I, A] =
    Middleware[({type T[A] = OptionT[F, A]})#T, UserAwareRequest[F, I, A], Response[F], Request[F], Response[F]]

  object UserAwareService {
    def apply[I, A, F[_]](
        pf: PartialFunction[UserAwareRequest[F, I, A], F[Response[F]]]
    )(implicit F: Monad[F]): UserAwareService[I, A, F] =
      Kleisli(
        req =>
          pf.andThen(OptionT.liftF(_))
            .applyOrElse(req, Function.const(OptionT.none[F, Response[F]]))
      )

    def apply[I, A, F[_]](
        pf: PartialFunction[UserAwareRequest[F, I, A], F[Response[F]]],
        andThen: (Response[F], Option[(I, A)]) => OptionT[F, Response[F]]
    )(implicit F: Monad[F]): UserAwareService[I, A, F] =
      Kleisli(
        req =>
          pf.andThen(OptionT.liftF(_))
            .applyOrElse(req, Function.const(OptionT.none[F, Response[F]]))
            .flatMap(r => andThen(r, req.maybe))
      )

    def extract[F[_]: Monad, I, Auth](
        authedStuff: Kleisli[({type T[A] = OptionT[F, A]})#T, Request[F], SecuredRequest[F, I, Auth]]
    ): UserAwareMiddleware[F, I, Auth] =
      service => {
        Kleisli { (r: Request[F]) =>
          OptionT.liftF(
            authedStuff
              .map(r => UserAwareRequest(r.request, Some((r.identity, r.authenticator))))
              .run(r)
              .getOrElse(UserAwareRequest(r, None))
              .flatMap(service.mapF(o => o.getOrElse(Response[F](Status.NotFound))).run)
          )
        }
      }
  }

  object asAware {

    /** Matcher for the http4s dsl
      * @param ar
      * @tparam F
      * @tparam A
      * @tparam I
      * @return
      */
    def unapply[F[_], I, A](ar: UserAwareRequest[F, I, A]): Option[(Request[F], Option[(I, A)])] =
      Some(ar.request -> ar.maybe)
  }

  /** Common cookie settings for cookie-based authenticators
    *
    * @param cookieName
    * @param secure
    * @param httpOnly
    * @param domain
    * @param path
    * @param extension
    */
  final case class TSecCookieSettings(
      cookieName: String = "tsec-auth-cookie",
      secure: Boolean,
      httpOnly: Boolean = true,
      domain: Option[String] = None,
      path: Option[String] = None,
      sameSite: Option[SameSite] = SameSite.Lax.some,
      extension: Option[String] = None,
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration]
  )

  final case class TSecTokenSettings(
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration]
  )

  final case class TSecJWTSettings(
      headerName: String = "X-TSec-JWT",
      expiryDuration: FiniteDuration,
      maxIdle: Option[FiniteDuration]
  )

  def cookieFromRequest[F[_]: Monad](name: String, request: Request[F]): OptionT[F, RequestCookie] =
    OptionT.fromOption[F](request.headers.get[org.http4s.headers.Cookie].flatMap(_.values.find(_.name === name)))

  def unliftedCookieFromRequest[F[_]](name: String, request: Request[F]): Option[RequestCookie] =
    request.headers.get[org.http4s.headers.Cookie].flatMap(_.values.find(_.name === name))

  def extractBearerToken[F[_]: Monad](request: Request[F]): Option[String] =
    request.headers.get[Authorization].flatMap { t =>
      t.credentials match {
        case Credentials.Token(scheme, token) if scheme == AuthScheme.Bearer =>
          Some(token)
        case _ => None
      }
    }

  def buildBearerAuthHeader(content: String): Authorization =
    Authorization(Credentials.Token(AuthScheme.Bearer, content))

  private[tsec] implicit val InstantLongDecoder: Decoder[Instant] = new Decoder[Instant] {
    def apply(c: HCursor): Either[DecodingFailure, Instant] =
      c.value
        .as[Long]
        .flatMap(
          l =>
            Either
              .catchNonFatal(Instant.ofEpochSecond(l))
              .leftMap(_ => DecodingFailure("InvalidEpoch", Nil))
        )
  }


  private[tsec] implicit val InstantLongEncoder: Encoder[Instant] = new Encoder[Instant] {
    def apply(a: Instant): Json = Json.fromLong(a.getEpochSecond)
  }

  private[tsec] def uuidFromRaw[F[_]: Sync](string: String): F[UUID] =
    Sync[F].delay(UUID.fromString(string))

  implicit class AuthenticatorSyntax[A](val a: A) extends AnyVal {
    def isExpired(now: Instant)(implicit A: AuthToken[A]): Boolean =
      A.isExpired(a, now)

    def isTimedOut(now: Instant, timeOut: FiniteDuration)(implicit A: AuthToken[A]): Boolean =
      A.isTimedOut(a, now, timeOut)
  }

  private[tsec] object AuthenticationFailure extends TSecError {
    def cause: String = "Authentication Failure"
  }

  private[tsec] def cataOption[F[_], A](a: Option[A])(implicit F: Sync[F]): F[A] =
    a.fold[F[A]](F.raiseError(AuthenticationFailure))(F.pure)

  private[tsec] implicit class AuthOptionTSyntax[F[_], A](val o: OptionT[F, A]) extends AnyVal {
    def orAuthFailure(implicit F: Sync[F]): F[A] =
      o.getOrElseF(F.raiseError(AuthenticationFailure))
  }
}
