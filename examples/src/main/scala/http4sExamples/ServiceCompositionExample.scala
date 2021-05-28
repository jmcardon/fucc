package http4sExamples

import cats.effect.IO
import cats.implicits._
import http4sExamples.BearerTokenExample.{Auth, userStore}
import http4sExamples.ExampleAuthHelpers.{Role, User}
import org.http4s.{HttpRoutes, Response, Status}
import org.http4s.dsl.io.{->, /, DELETE, GET, PUT, Root}
import tsec.authentication.{SecuredRequest, TSecAuthService, TSecBearerToken, asAuthed}
import tsec.authorization.BasicRBAC

object ServiceCompositionExample {
  // Create users
  val adminUser: User = User(0, 18, "admin", Role.Administrator)
  val customerUser: User = User(1, 15, "user", Role.Customer)

  // Store them
  userStore.put(adminUser).unsafeRunSync()
  userStore.put(customerUser).unsafeRunSync()

  // Create Tokens
  val adminToken = Auth.authenticator.create(adminUser.id).unsafeRunSync()
  val userToken = Auth.authenticator.create(customerUser.id).unsafeRunSync()

  // Set Authorization policy
  val rbacPolicy = BasicRBAC[IO, Role, User, TSecBearerToken[Int]](Role.Administrator)

  type PartialEndpoint = PartialFunction[SecuredRequest[IO, User, TSecBearerToken[Int]], IO[Response[IO]]]
  val deleteItem: PartialEndpoint = {
    case DELETE -> Root / "items" asAuthed _ => IO(Response(status = Status.NoContent))
  }

  val putItem: PartialEndpoint = {
    case PUT -> Root / "items" asAuthed _ => IO(Response(status = Status.Created))
  }

  val getItem = HttpRoutes.of[IO] {
    case GET -> Root / "items" => IO(Response(status = Status.Ok))
  }

  // Service Composition
  val securedService =
    getItem <+>
      Auth.liftService(TSecAuthService.withAuthorizationHandler(rbacPolicy)(deleteItem, TSecAuthService(putItem).run))
}
