package tsec.authentication

import cats.data.OptionT
import cats.effect.IO
import org.http4s._
import org.http4s.dsl.io._
import tsec.TestSpec
import tsec.csrf.{CSRFToken, TSecCSRF}
import tsec.keygen.symmetric.IdKeyGen
import tsec.mac.jca._

class CSRFSpec extends TestSpec {

  val dummyService: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root =>
      Thread.sleep(1) //Necessary to advance the clock
      Ok()
    case POST -> Root =>
      Thread.sleep(1) //Necessary to advance the clock
      Ok()
  }

  val dummyRequest: Request[IO]       = Request[IO](method = Method.POST)
  val passThroughRequest: Request[IO] = Request[IO]()
  val orElse: Response[IO]            = Response[IO](Status.Unauthorized)

  def testCSRFWithMac[A](implicit mac: JCAMessageAuth[IO, A], keygen: IdKeyGen[A, MacSigningKey]) = {
    behavior of s"CSRF signing using " + mac.algorithm

    val newKey   = keygen.generateKey
    val tsecCSRF = TSecCSRF[IO, A](newKey)

    it should "check for an equal token properly" in {
      (for {
        t  <- OptionT.liftF(tsecCSRF.generateToken)
        eq <- tsecCSRF.checkEqual(t, t)
      } yield eq).getOrElse(false).unsafeRunSync() mustBe true
    }

    it should "not validate different tokens" in {
      (for {
        t1 <- OptionT.liftF(tsecCSRF.generateToken)
        t2 <- OptionT.liftF(tsecCSRF.generateToken)
        eq <- tsecCSRF.checkEqual(t1, t2)
      } yield eq).getOrElse(false).unsafeRunSync() mustBe false
    }

    behavior of s"CSRF middleware using " + mac.algorithm

    it should "pass through and embed for a fresh request in a safe method" in {

      val response = tsecCSRF.validate()(dummyService)(passThroughRequest).getOrElse(orElse).unsafeRunSync()

      response.status mustBe Status.Ok
      response.cookies.exists(_.name == tsecCSRF.cookieName) mustBe true
    }

    it should "fail and not embed a new token for a safe method but invalid cookie" in {

      val response = tsecCSRF
        .validate()(dummyService)(passThroughRequest.addCookie(RequestCookie(tsecCSRF.cookieName, "MOOSE")))
        .getOrElse(orElse)
        .unsafeRunSync()

      response.status mustBe Status.Unauthorized
      !response.cookies.exists(_.name == tsecCSRF.cookieName) mustBe true
    }

    it should "pass through and embed a slightly different token for a safe request" in {

      val (origToken, origRaw, response, newToken, newRaw) =
        (for {
          t1     <- OptionT.liftF[IO, CSRFToken](tsecCSRF.generateToken)
          raw1   <- tsecCSRF.extractRaw(t1)
          resp   <- tsecCSRF.validate()(dummyService)(passThroughRequest.addCookie(RequestCookie(tsecCSRF.cookieName, t1)))
          cookie <- OptionT.fromOption[IO](resp.cookies.find(_.name == tsecCSRF.cookieName))
          raw2   <- tsecCSRF.extractRaw(CSRFToken(cookie.content))
        } yield (t1, raw1, resp, CSRFToken(cookie.content), raw2))
          .getOrElse(throw new IllegalStateException("ruh orh"))
          .unsafeRunSync()

      response.status mustBe Status.Ok
      origToken mustNot be(newToken)
      origRaw mustBe newRaw
    }

    it should "validate for the correct csrf token" in {
      (for {
        token <- OptionT.liftF(tsecCSRF.generateToken)
        res <- tsecCSRF.validate()(dummyService)(
          dummyRequest.withHeaders(Headers(tsecCSRF.headerName -> token)).addCookie(tsecCSRF.cookieName, token)
        )
      } yield res).getOrElse(orElse).unsafeRunSync().status mustBe Status.Ok
    }

    it should "not validate if token is missing in both" in {
      (for {
        res <- tsecCSRF.validate()(dummyService)(dummyRequest)
      } yield res).getOrElse(orElse).unsafeRunSync().status mustBe Status.Unauthorized
    }

    it should "not validate for token missing in header" in {
      (for {
        token <- OptionT.liftF(tsecCSRF.generateToken)
        res <- tsecCSRF.validate()(dummyService)(
          dummyRequest.addCookie(tsecCSRF.cookieName, token)
        )
      } yield res).getOrElse(orElse).unsafeRunSync().status mustBe Status.Unauthorized
    }

    it should "not validate for token missing in cookie" in {
      (for {
        token <- OptionT.liftF(tsecCSRF.generateToken)
        res <- tsecCSRF.validate()(dummyService)(
          dummyRequest.withHeaders(Headers(tsecCSRF.headerName -> token))
        )
      } yield res).getOrElse(orElse).unsafeRunSync().status mustBe Status.Unauthorized
    }

    it should "not validate for different tokens" in {
      (for {
        token1 <- OptionT.liftF(tsecCSRF.generateToken)
        token2 <- OptionT.liftF(tsecCSRF.generateToken)
        res <- tsecCSRF.validate()(dummyService)(
          dummyRequest.withHeaders(Headers(tsecCSRF.headerName -> token1)).addCookie(tsecCSRF.cookieName, token2)
        )
      } yield res).getOrElse(orElse).unsafeRunSync().status mustBe Status.Unauthorized
    }

    it should "not return the same token to mitigate BREACH" in {
      (for {
        token <- OptionT.liftF(tsecCSRF.generateToken)
        raw1  <- tsecCSRF.extractRaw(token)
        res <- tsecCSRF.validate()(dummyService)(
          dummyRequest.withHeaders(Headers(tsecCSRF.headerName -> token)).addCookie(tsecCSRF.cookieName, token)
        )
        r    <- OptionT.fromOption[IO](res.cookies.find(_.name == tsecCSRF.cookieName).map(_.content))
        raw2 <- tsecCSRF.extractRaw(CSRFToken(r))
      } yield r != token && raw1 == raw2).getOrElse(false).unsafeRunSync() mustBe true
    }

    it should "not return a token for a failed CSRF check" in {
      val response = (for {
        token1 <- OptionT.liftF(tsecCSRF.generateToken)
        token2 <- OptionT.liftF(tsecCSRF.generateToken)
        res <- tsecCSRF.validate()(dummyService)(
          dummyRequest.withHeaders(Headers(tsecCSRF.headerName -> token1)).addCookie(tsecCSRF.cookieName, token2)
        )
      } yield res).getOrElse(Response.notFound).unsafeRunSync()

      response.status mustBe Status.Unauthorized
      !response.cookies.exists(_.name == tsecCSRF.cookieName) mustBe true
    }

  }

}
