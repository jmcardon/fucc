package http4sExamples

import cats.effect.IO
import http4sExamples.ServiceCompositionExample._
import org.http4s.implicits._
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, Http4sLiteralSyntax, Method, Request, Status, Uri}
import tsec.TestSpec

class ServiceCompositionTest extends TestSpec {

  val myApp = securedService.orNotFound

  // Test Requests
  val getReq = Request[IO](method = Method.GET, uri = uri"items")
  val putReq = Request[IO](method = Method.PUT, uri = uri"items")
    .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, userToken.id)))
  val delReq = Request[IO](method = Method.DELETE, uri = uri"items")
    .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, adminToken.id)))

  myApp.run(getReq).unsafeRunSync().status mustBe Status.Ok
  myApp.run(putReq).unsafeRunSync().status mustBe Status.Created
  myApp.run(delReq).unsafeRunSync().status mustBe Status.NoContent

  // Some more tests
  val putReqUnAuth = Request[IO](method = Method.PUT, uri = uri"items")
  val delReqUnAuth = Request[IO](method = Method.DELETE, uri = uri"items")
  val delReqUnauth2 = Request[IO](method = Method.DELETE, uri = uri"items")
    .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, userToken.id)))

  myApp.run(putReqUnAuth).unsafeRunSync().status mustBe Status.Unauthorized
  myApp.run(delReqUnAuth).unsafeRunSync().status mustBe Status.Unauthorized
  myApp.run(delReqUnauth2).unsafeRunSync().status mustBe Status.NotFound
}


