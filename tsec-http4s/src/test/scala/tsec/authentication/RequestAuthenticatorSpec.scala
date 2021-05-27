package tsec.authentication

import cats.data.OptionT
import cats.effect.IO
import cats.syntax.either._
import io.circe.Json
import io.circe.generic.auto._
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import tsec.authorization.BasicRBAC

class RequestAuthenticatorSpec extends AuthenticatorSpec {

  def requestAuthTests[A](title: String, authSpec: AuthSpecTester[A]): Unit = {

    behavior of "SecuredRequests: " + title

    val dummyBob = DummyUser(0)

    val requestAuth = SecuredRequestHandler(authSpec.auth)

    //Add bob to the db
    authSpec.dummyStore.put(dummyBob).unsafeRunSync()

    val onlyAdmins = BasicRBAC[IO, DummyRole, DummyUser, A](DummyRole.Admin)
    val everyone   = BasicRBAC.all[IO, DummyRole, DummyUser, A]

    val testService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
    })

    val adminService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService.withAuthorization(onlyAdmins) {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
    })

    val everyoneService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService.withAuthorization(everyone) {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
    })

    val insaneService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService {
      case request @ GET -> Root / "api" asAuthed hi =>
        IO.raiseError(new IllegalArgumentException)
    })

    val customService: TSecAuthService[DummyUser, A, IO] = TSecAuthService {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok()
    }

    val userAwareService: UserAwareService[DummyUser, A, IO] = UserAwareService {
      case GET -> Root asAware u =>
        u match {
          case Some((user, auth)) =>
            Ok()

          case None =>
            BadRequest()
        }
    }

    val liftedUserAware: HttpRoutes[IO] = requestAuth.liftUserAware(userAwareService)

    it should "TryExtractRaw properly" in {

      val response: OptionT[IO, Option[String]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
      } yield authSpec.auth.extractRawOption(embedded)
      response
        .getOrElse(None)
        .unsafeRunSync()
        .isDefined mustBe true
    }

    it should "Return a proper deserialized user" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "fail on an expired token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth    <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        expired <- OptionT.liftF(authSpec.expireAuthenticator(auth))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), expired)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "work on a renewed token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth    <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        expired <- OptionT.liftF(authSpec.expireAuthenticator(auth))
        renewed <- OptionT.liftF(authSpec.auth.renew(expired))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "Reject an invalid token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(authSpec.wrongKeyAuthenticator)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    //note: we feed it "discarded" because stateless tokens rely on this.
    it should "Fail on a discarded token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth      <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        discarded <- OptionT.liftF(requestAuth.authenticator.discard(auth))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), discarded)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "authorize for an allowed endpoint" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- everyoneService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "not authorize for a gated endpoint" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- adminService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound[IO])
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "use the specified response when onNotAuthorized is specified" in {
      val req      = Request[IO](uri = Uri.unsafeFromString("/api"))
      val response = requestAuth.liftService(customService, _ => IO.pure(Response[IO](Status.BadGateway)))(req)

      response.getOrElse(Response.notFound).map(_.status).unsafeRunSync() mustBe Status.BadGateway
    }

    it should "catch unhandled errors into unauthorized" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- insaneService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "extract properly for a user aware service" in {

      val response: OptionT[IO, (Status, Status)] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
        embedded    = authSpec.embedInRequest(Request[IO](GET), auth)
        nonEmbedded = Request[IO](GET)
        s1 <- liftedUserAware.run(embedded).map(_.status)
        s2 <- liftedUserAware.run(nonEmbedded).map(_.status)
      } yield (s1, s2)
      val (l, r) = response
        .getOrElse((NotFound, NotFound))
        .unsafeRunSync()

      l mustBe Ok
      r mustBe BadRequest
    }

    if (authSpec.auth.maxIdle.isEmpty) {
      it should "no-op on a timed out token" in {
        val response: OptionT[IO, Response[IO]] = for {
          auth     <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
          timedOut <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
          embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), timedOut)
          res <- testService(embedded)
        } yield res
        response
          .getOrElse(Response.notFound)
          .map(_.status)
          .unsafeRunSync() mustBe Status.Ok
      }
    } else {

      it should "work on a refreshed token" in {
        val response: OptionT[IO, (Status, Status)] = for {
          auth    <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
          expired <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
          embedded1 = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), expired)
          res1    <- testService(embedded1)
          renewed <- OptionT.liftF(authSpec.auth.refresh(expired))
          embedded2 = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
          res2 <- testService(embedded2)
        } yield (res1.status, res2.status)
        response
          .getOrElse((Status.NotFound, Status.NotFound))
          .unsafeRunSync() mustBe ((Status.Unauthorized, Status.Ok))
      }

      it should "fail on a timed out token" in {
        val response: OptionT[IO, Response[IO]] = for {
          auth     <- OptionT.liftF(requestAuth.authenticator.create(dummyBob.id))
          timedOut <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
          embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), timedOut)
          res <- testService(embedded)
        } yield res
        response
          .getOrElse(Response.notFound)
          .map(_.status)
          .unsafeRunSync() mustBe Status.Unauthorized
      }
    }
  }

  def statelessReqAuthTests[A](title: String, authSpec: StatelessSpecTester[A]): Unit = {

    behavior of "SecuredRequests: " + title

    val dummyBob = DummyUser(0)

    val requestAuth = SecuredRequestHandler(authSpec.auth)

    val onlyAdmins = BasicRBAC[IO, DummyRole, DummyUser, A](DummyRole.Admin)
    val everyone   = BasicRBAC.all[IO, DummyRole, DummyUser, A]

    val testService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
    })

    val adminService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService.withAuthorization(onlyAdmins) {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
    })

    val everyoneService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService.withAuthorization(everyone) {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok(hi.asJson)
    })

    val insaneService: HttpRoutes[IO] = requestAuth.liftService(TSecAuthService {
      case request @ GET -> Root / "api" asAuthed hi =>
        IO.raiseError(new IllegalArgumentException)
    })

    val customService: TSecAuthService[DummyUser, A, IO] = TSecAuthService {
      case request @ GET -> Root / "api" asAuthed hi =>
        Ok()
    }

    val userAwareService: UserAwareService[DummyUser, A, IO] = UserAwareService {
      case GET -> Root asAware u =>
        u match {
          case Some((user, auth)) =>
            Ok()

          case None =>
            BadRequest()
        }
    }

    val liftedUserAware: HttpRoutes[IO] = requestAuth.liftUserAware(userAwareService)

    it should "TryExtractRaw properly" in {

      val response: OptionT[IO, Option[String]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
      } yield authSpec.auth.extractRawOption(embedded)
      response
        .getOrElse(None)
        .unsafeRunSync()
        .isDefined mustBe true
    }

    it should "Return a proper deserialized user" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "fail on an expired token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth    <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        expired <- OptionT.liftF(authSpec.expireAuthenticator(auth))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), expired)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "work on a renewed token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth    <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        expired <- OptionT.liftF(authSpec.expireAuthenticator(auth))
        renewed <- OptionT.liftF(authSpec.auth.renew(expired))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "Reject an invalid token" in {

      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(authSpec.wrongKeyAuthenticator)
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    //note: we feed it "discarded" because stateless tokens rely on this.
    it should "Fail on a discarded token" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth      <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        discarded <- OptionT.liftF(requestAuth.authenticator.discard(auth))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), discarded)
        res <- testService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "authorize for an allowed endpoint" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- everyoneService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .flatMap(_.attemptAs[Json].value.map(_.flatMap(_.as[DummyUser])))
        .unsafeRunSync() mustBe Right(dummyBob)
    }

    it should "not authorize for a gated endpoint" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- adminService(embedded)
      } yield res
      response
        .getOrElse(Response.notFound)
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "use the specified response when onNotAuthorized is specified" in {
      val req      = Request[IO](uri = Uri.unsafeFromString("/api"))
      val response = requestAuth.liftService(customService, _ => IO.pure(Response[IO](Status.BadGateway)))(req)

      response.getOrElse(Response.notFound).map(_.status).unsafeRunSync() mustBe Status.BadGateway
    }

    it should "catch unhandled errors into unauthorized" in {
      val response: OptionT[IO, Response[IO]] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), auth)
        res <- insaneService(embedded)
      } yield res
      response
        .getOrElse(Response[IO](status = Status.Forbidden))
        .map(_.status)
        .unsafeRunSync() mustBe Status.Unauthorized
    }

    it should "extract properly for a user aware service" in {

      val response: OptionT[IO, (Status, Status)] = for {
        auth <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
        embedded    = authSpec.embedInRequest(Request[IO](GET), auth)
        nonEmbedded = Request[IO](GET)
        s1 <- liftedUserAware.run(embedded).map(_.status)
        s2 <- liftedUserAware.run(nonEmbedded).map(_.status)
      } yield (s1, s2)
      val (l, r) = response
        .getOrElse((NotFound, NotFound))
        .unsafeRunSync()

      l mustBe Ok
      r mustBe BadRequest
    }

    if (authSpec.auth.maxIdle.isEmpty) {
      it should "no-op on a timed out token" in {
        val response: OptionT[IO, Response[IO]] = for {
          auth     <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
          timedOut <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
          embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), timedOut)
          res <- testService(embedded)
        } yield res
        response
          .getOrElse(Response.notFound)
          .map(_.status)
          .unsafeRunSync() mustBe Status.Ok
      }
    } else {

      it should "work on a refreshed token" in {
        val response: OptionT[IO, (Status, Status)] = for {
          auth    <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
          expired <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
          embedded1 = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), expired)
          res1    <- testService(embedded1)
          renewed <- OptionT.liftF(authSpec.auth.refresh(expired))
          embedded2 = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), renewed)
          res2 <- testService(embedded2)
        } yield (res1.status, res2.status)
        response
          .getOrElse((Status.NotFound, Status.NotFound))
          .unsafeRunSync() mustBe ((Status.Unauthorized, Status.Ok))
      }

      it should "fail on a timed out token" in {
        val response: OptionT[IO, Response[IO]] = for {
          auth     <- OptionT.liftF(requestAuth.authenticator.create(dummyBob))
          timedOut <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
          embedded = authSpec.embedInRequest(Request[IO](uri = Uri.unsafeFromString("/api")), timedOut)
          res <- testService(embedded)
        } yield res
        response
          .getOrElse(Response.notFound)
          .map(_.status)
          .unsafeRunSync() mustBe Status.Unauthorized
      }
    }
  }

}
