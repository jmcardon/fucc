package tsec.authentication

import cats.ApplicativeError
import cats.MonadError
import cats.data.{Kleisli, OptionT}
import cats.syntax.all._
import org.http4s._
import org.log4s._
import tsec.authorization._

sealed abstract class SecuredRequestHandler[F[_], Identity, User, Auth](
    val authenticator: Authenticator[F, Identity, User, Auth]
)(implicit F: MonadError[F, Throwable], ME: MonadError[({ type G[A] = Kleisli[({type T[A] = OptionT[F, A]})#T, Request[F], A]})#G, Throwable]) {

  private[this] val cachedUnauthorized: Response[F]                       = Response[F](Status.Unauthorized)
  private[this] val defaultNotAuthenticated: Request[F] => F[Response[F]] = _ => F.pure(cachedUnauthorized)

  /** Lift an Authenticated Service into an HttpRoutes **/
  def liftService(
      service: TSecAuthService[User, Auth, F],
      onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
  ): HttpRoutes[F] = {
    val middleware = TSecMiddleware(Kleisli(authenticator.extractAndValidate), onNotAuthenticated)

    ME.handleErrorWith(middleware(service)) { e: Throwable =>
      SecuredRequestHandler.logger.error(e)("Caught unhandled exception in authenticated service")
      Kleisli.liftF(OptionT.pure(cachedUnauthorized))
    }
  }

  def liftWithFallthrough(
      service: TSecAuthService[User, Auth, F],
      onNotAuthenticated: Request[F] => F[Response[F]] = defaultNotAuthenticated
  ): HttpRoutes[F] = {
    val middleware = TSecMiddleware.withFallthrough(Kleisli(authenticator.extractAndValidate), onNotAuthenticated)

    ME.handleErrorWith(middleware(service)) { e: Throwable =>
      SecuredRequestHandler.logger.error(e)("Caught unhandled exception in authenticated service")
      Kleisli.liftF(OptionT.pure(cachedUnauthorized))
    }
  }

  def liftUserAware(
      service: UserAwareService[User, Auth, F]
  ): HttpRoutes[F] = {
    val middleware = UserAwareService.extract(Kleisli(authenticator.extractAndValidate))

    ME.handleErrorWith(middleware(service)) { e: Throwable =>
      SecuredRequestHandler.logger.error(e)("Caught unhandled exception in authenticated service")
      Kleisli.liftF(OptionT.pure(cachedUnauthorized))
    }
  }

}

object SecuredRequestHandler {
  private[authentication] val logger = getLogger("tsec.authentication.SecureRequestHandler")

  /** Build our SecuredRequestHandler detecting whether it is rolling window or not **/
  def apply[F[_], Identity, User, Auth](
      authenticator: Authenticator[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    if (authenticator.maxIdle.isDefined) {
      rollingWindow[F, Identity, User, Auth](authenticator)
    } else {
      default[F, Identity, User, Auth](authenticator)
    }

  /** Sliding/Rolling Window expiry Construction **/
  private[tsec] def rollingWindow[F[_], Identity, User, Auth](
      authenticator: Authenticator[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {}

  /** Default Construction **/
  private[tsec] def default[F[_], Identity, User, Auth](
      authenticator: Authenticator[F, Identity, User, Auth]
  )(implicit F: MonadError[F, Throwable]): SecuredRequestHandler[F, Identity, User, Auth] =
    new SecuredRequestHandler[F, Identity, User, Auth](authenticator) {}

}
