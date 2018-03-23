package tsec

import java.time.Instant
import java.util.UUID

import cats.data.{Kleisli, OptionT}
import cats.implicits._
import cats.{Applicative, Monad}
import io.circe._
import org.http4s._
import org.http4s.headers.{Authorization, Cookie => C}
import org.http4s.server.Middleware
import tsec.authorization.{Authorization => TAuth}

import scala.concurrent.duration.FiniteDuration
import scala.util.control.NonFatal

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
    Middleware[OptionT[F, ?], SecuredRequest[F, I, A], Response[F], Request[F], Response[F]]

  object TSecMiddleware {
    def apply[F[_]: Monad, I, Auth](
        authedStuff: Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, I, Auth]],
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
        authedStuff: Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, I, Auth]],
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
  type TSecAuthService[I, A, F[_]] = Kleisli[OptionT[F, ?], SecuredRequest[F, I, A], Response[F]]

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

    def withAuthorization[I, A, F[_]](auth: TAuth[F, I, A])(
        pf: PartialFunction[SecuredRequest[F, I, A], F[Response[F]]]
    )(implicit F: Monad[F]): TSecAuthService[I, A, F] =
      Kleisli { req: SecuredRequest[F, I, A] =>
        auth
          .isAuthorized(req)
          .flatMap(_ => pf.andThen(OptionT.liftF(_)).applyOrElse(req, Function.const(OptionT.none)))
      }

    /** The empty service (all requests fallthrough).
      * @tparam F - Ignored
      * @tparam I - Ignored
      * @tparam A - Ignored
      * @return
      */
    def empty[A, It, F[_]: Applicative]: TSecAuthService[I, A, F] =
      Kleisli.liftF(OptionT.none)
  }

  type UserAwareService[I, A, F[_]] =
    Kleisli[OptionT[F, ?], UserAwareRequest[F, I, A], Response[F]]

  type UserAwareMiddleware[F[_], I, A] =
    Middleware[OptionT[F, ?], UserAwareRequest[F, I, A], Response[F], Request[F], Response[F]]

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
        authedStuff: Kleisli[OptionT[F, ?], Request[F], SecuredRequest[F, I, Auth]]
    ): UserAwareMiddleware[F, I, Auth] =
      service => {
        Kleisli { r: Request[F] =>
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

  def cookieFromRequest[F[_]: Monad](name: String, request: Request[F]): OptionT[F, Cookie] =
    OptionT.fromOption[F](C.from(request.headers).flatMap(_.values.find(_.name === name)))

  def unliftedCookieFromRequest[F[_]](name: String, request: Request[F]): Option[Cookie] =
    C.from(request.headers).flatMap(_.values.find(_.name === name))

  def extractBearerToken[F[_]: Monad](request: Request[F]): Option[String] =
    request.headers.get(Authorization).flatMap { t =>
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

  def uuidFromRaw[F[_]: Applicative](string: String): OptionT[F, UUID] =
    try OptionT.pure(UUID.fromString(string))
    catch {
      case NonFatal(e) => OptionT.none
    }
}
