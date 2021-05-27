package tsec.authentication

import cats.Applicative
import cats.ApplicativeError
import cats.data.OptionT
import cats.effect.IO
import cats.{Eq, MonadError}
import cats.syntax.applicativeError._
import cats.instances.string._
import org.http4s._
import org.scalacheck._
import org.scalatest.BeforeAndAfterEach
import tsec.TestSpec
import tsec.authorization.{AuthGroup, AuthorizationInfo, SimpleAuthEnum}

import scala.collection.mutable

sealed abstract case class DummyRole(repr: String)
object DummyRole extends SimpleAuthEnum[DummyRole, String] {
  implicit object Admin extends DummyRole("Admin")
  implicit object User  extends DummyRole("User")
  implicit object Other extends DummyRole("Other")
  implicit object Err   extends DummyRole("Err")

  def getRepr(t: DummyRole): String = t.repr

  protected val values: AuthGroup[DummyRole] = AuthGroup(Admin, Other)
  implicit val eq: Eq[DummyRole] = new Eq[DummyRole] {
    def eqv(x: DummyRole, y: DummyRole): Boolean = x == y
  }
}

case class DummyUser(id: Int, name: String = "bob", role: DummyRole = DummyRole.Other)

object DummyUser {
  implicit val role: AuthorizationInfo[IO, DummyRole, DummyUser] = new AuthorizationInfo[IO, DummyRole, DummyUser] {
    def fetchInfo(u: DummyUser): IO[DummyRole] = IO.pure(u.role)
  }
}

/** An inner class for defining tests against an authenticator with a backing store
  * This contains utilities that are not present currently under the `Authenticator`
  * class that are necessary for testing.
  *
  */
protected[authentication] abstract case class AuthSpecTester[Auth](
    auth: Authenticator[IO, Int, DummyUser, Auth],
    dummyStore: BackingStore[IO, Int, DummyUser]
) {

  def embedInRequest(request: Request[IO], authenticator: Auth): Request[IO]

  def expireAuthenticator(b: Auth): IO[Auth]

  def timeoutAuthenticator(b: Auth): IO[Auth]

  def wrongKeyAuthenticator: IO[Auth]
}

protected[authentication] abstract case class StatelessSpecTester[Auth](
    auth: Authenticator[IO, DummyUser, DummyUser, Auth]
) {

  def embedInRequest(request: Request[IO], authenticator: Auth): Request[IO]

  def expireAuthenticator(b: Auth): IO[Auth]

  def timeoutAuthenticator(b: Auth): IO[Auth]

  def wrongKeyAuthenticator: IO[Auth]
}

abstract class AuthenticatorSpec extends TestSpec with BeforeAndAfterEach {

  implicit val genDummy: Arbitrary[DummyUser] = Arbitrary(for {
    i <- Gen.chooseNum[Int](0, Int.MaxValue)
    s <- Gen.alphaNumStr
  } yield DummyUser(i, s))

  def errorToNone[F[_]: Applicative, A](t: Throwable): OptionT[F, A] =
    OptionT.none[F, A]

  def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: MonadError[F, Throwable]) = new BackingStore[F, I, V] {
    val storageMap = mutable.HashMap.empty[I, V]

    def put(elem: V): F[V] = {
      val map = storageMap.put(getId(elem), elem)
      F.pure(elem)
    }

    def get(id: I): OptionT[F, V] =
      OptionT.fromOption[F](storageMap.get(id))

    def update(v: V): F[V] = {
      storageMap.update(getId(v), v)
      F.pure(v)
    }

    def delete(id: I): F[Unit] =
      storageMap.remove(id) match {
        case Some(_) => F.unit
        case None =>
          F.raiseError(new IllegalArgumentException)
      }

    def dAll(): Unit = storageMap.clear()
  }

  def AuthenticatorTest[A](title: String, authSpec: AuthSpecTester[A])(
      implicit AE: ApplicativeError[({ type F[A] = OptionT[IO, A]})#F, Throwable]
  ) = {
    behavior of title

    it should "Create, embed and extract properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _           <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth        <- OptionT.liftF(authSpec.auth.create(dummy1.id))
          fromRequest <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), auth))
          _           <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield fromRequest)
          .handleErrorWith(errorToNone)
          .value

        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
        extracted.map(_.identity) mustBe Some(dummy1)
      }
    }

    it should "Not validate for an expired token" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _       <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth    <- OptionT.liftF(authSpec.auth.create(dummy1.id))
          expired <- OptionT.liftF(authSpec.expireAuthenticator(auth))
          updated <- OptionT.liftF(authSpec.auth.update(expired))
          req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
        } yield req2)
          .handleErrorWith(_ => OptionT.liftF(authSpec.dummyStore.delete(dummy1.id)).flatMap(_ => OptionT.none)) // Only delete if it fails as expected
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    it should "renew properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _        <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth     <- OptionT.liftF(authSpec.auth.create(dummy1.id))
          expired  <- OptionT.liftF(authSpec.expireAuthenticator(auth))
          updated1 <- OptionT.liftF(authSpec.auth.update(expired))
          renewed  <- OptionT.liftF(authSpec.auth.renew(updated1))
          req2     <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), renewed))
          _        <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(errorToNone)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
      }
    }

    it should "Not validate for a token with a different key/incorrect" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _     <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          wrong <- OptionT.liftF(authSpec.wrongKeyAuthenticator)
          req2  <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), wrong))
          _     <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(_ => OptionT.liftF(authSpec.dummyStore.delete(dummy1.id)).flatMap(_ => OptionT.none))
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    it should "discard a token properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _         <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth      <- OptionT.liftF(authSpec.auth.create(dummy1.id))
          discarded <- OptionT.liftF(authSpec.auth.discard(auth))
          req2      <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), discarded))
          _         <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield req2)
          .handleErrorWith(errorToNone)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    if (authSpec.auth.maxIdle.isDefined) {

      it should "Not validate for a token past the timeout" in {
        forAll { (dummy1: DummyUser) =>
          val results = (for {
            _       <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
            auth    <- OptionT.liftF(authSpec.auth.create(dummy1.id))
            expired <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
            updated <- OptionT.liftF(authSpec.auth.update(expired))
            req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
          } yield req2)
            .handleErrorWith(_ => OptionT.liftF(authSpec.dummyStore.delete(dummy1.id)).flatMap(_ => OptionT.none))
            .value
          val extracted = results.unsafeRunSync()
          extracted.isEmpty mustBe true
        }
      }

      it should "refresh properly" in {
        forAll { (dummy1: DummyUser) =>
          val results = (for {
            _        <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
            auth     <- OptionT.liftF(authSpec.auth.create(dummy1.id))
            expired  <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
            updated1 <- OptionT.liftF(authSpec.auth.update(expired))
            renewed  <- OptionT.liftF(authSpec.auth.refresh(updated1))
            req2     <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), renewed))
            _        <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
          } yield req2)
            .handleErrorWith(errorToNone)
            .value
          val extracted = results.unsafeRunSync()
          extracted.isEmpty mustBe false
        }
      }
    } else {
      it should "no-op validate for a timed out token" in {
        forAll { (dummy1: DummyUser) =>
          val results = (for {
            _       <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
            auth    <- OptionT.liftF(authSpec.auth.create(dummy1.id))
            expired <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
            updated <- OptionT.liftF(authSpec.auth.update(expired))
            req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
          } yield req2)
            .handleErrorWith(_ => OptionT.liftF(authSpec.dummyStore.delete(dummy1.id)).flatMap(_ => OptionT.none))
            .value
          val extracted = results.unsafeRunSync()
          extracted.isDefined mustBe true
        }
      }
    }
  }

  def StatelessAuthenticatorTest[A](title: String, authSpec: StatelessSpecTester[A])(
      implicit AE: ApplicativeError[({ type F[A] = OptionT[IO, A]})#F, Throwable]
  ) = {
    behavior of title

    it should "Create, embed and extract properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          auth        <- OptionT.liftF(authSpec.auth.create(dummy1))
          fromRequest <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), auth))
        } yield fromRequest)
          .handleErrorWith(errorToNone)
          .value

        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
        extracted.map(_.identity) mustBe Some(dummy1)
      }
    }

    it should "Not validate for an expired token" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          auth    <- OptionT.liftF(authSpec.auth.create(dummy1))
          expired <- OptionT.liftF(authSpec.expireAuthenticator(auth))
          updated <- OptionT.liftF(authSpec.auth.update(expired))
          req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
        } yield req2)
          .handleErrorWith(errorToNone) // Only delete if it fails as expected
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    it should "renew properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          auth     <- OptionT.liftF(authSpec.auth.create(dummy1))
          expired  <- OptionT.liftF(authSpec.expireAuthenticator(auth))
          updated1 <- OptionT.liftF(authSpec.auth.update(expired))
          renewed  <- OptionT.liftF(authSpec.auth.renew(updated1))
          req2     <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), renewed))
        } yield req2)
          .handleErrorWith(errorToNone)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
      }
    }

    it should "Not validate for a token with a different key/incorrect" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          wrong <- OptionT.liftF(authSpec.wrongKeyAuthenticator)
          req2  <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), wrong))
        } yield req2)
          .handleErrorWith(errorToNone)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    it should "discard a token properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          auth      <- OptionT.liftF(authSpec.auth.create(dummy1))
          discarded <- OptionT.liftF(authSpec.auth.discard(auth))
          req2      <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), discarded))
        } yield req2)
          .handleErrorWith(errorToNone)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }

    if (authSpec.auth.maxIdle.isDefined) {

      it should "Not validate for a token past the timeout" in {
        forAll { (dummy1: DummyUser) =>
          val results = (for {
            auth    <- OptionT.liftF(authSpec.auth.create(dummy1))
            expired <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
            updated <- OptionT.liftF(authSpec.auth.update(expired))
            req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
          } yield req2)
            .handleErrorWith(errorToNone)
            .value
          val extracted = results.unsafeRunSync()
          extracted.isEmpty mustBe true
        }
      }

      it should "refresh properly" in {
        forAll { (dummy1: DummyUser) =>
          val results = (for {
            auth     <- OptionT.liftF(authSpec.auth.create(dummy1))
            expired  <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
            updated1 <- OptionT.liftF(authSpec.auth.update(expired))
            renewed  <- OptionT.liftF(authSpec.auth.refresh(updated1))
            req2     <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), renewed))
          } yield req2)
            .handleErrorWith(errorToNone)
            .value
          val extracted = results.unsafeRunSync()
          extracted.isEmpty mustBe false
        }
      }
    } else {
      it should "no-op validate for a timed out token" in {
        forAll { (dummy1: DummyUser) =>
          val results = (for {
            auth    <- OptionT.liftF(authSpec.auth.create(dummy1))
            expired <- OptionT.liftF(authSpec.timeoutAuthenticator(auth))
            updated <- OptionT.liftF(authSpec.auth.update(expired))
            req2    <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), updated))
          } yield req2)
            .handleErrorWith(errorToNone)
            .value
          val extracted = results.unsafeRunSync()
          extracted.isDefined mustBe true
        }
      }
    }
  }

}
