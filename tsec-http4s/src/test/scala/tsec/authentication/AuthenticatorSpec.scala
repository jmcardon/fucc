package tsec.authentication

import cats.data.OptionT
import cats.effect.IO
import cats.{Eq, MonadError}
import tsec.TestSpec
import org.http4s._
import cats.implicits._
import org.scalacheck._
import org.scalatest.{BeforeAndAfterEach, MustMatchers}
import org.scalatest.prop.PropertyChecks
import tsec.authorization.{AuthGroup, AuthorizationInfo, SimpleAuthEnum}

import scala.collection.mutable

sealed abstract case class DummyRole(repr: String)
object DummyRole extends SimpleAuthEnum[DummyRole, String] {
  implicit object Admin extends DummyRole("Admin")
  implicit object User  extends DummyRole("User")
  implicit object Other extends DummyRole("Other")
  implicit object Err   extends DummyRole("Err")

  val getRepr: (DummyRole) => String         = _.repr
  protected val values: AuthGroup[DummyRole] = AuthGroup(Admin, Other)
  val orElse: DummyRole                      = Err
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

/** An inner class for defining tests against an authenticator
  * This contains utilities that are not present currently under the `Authenticator`
  * class that are necessary for testing.
  *
  */
protected[authentication] abstract case class AuthSpecTester[Auth](
    auth: AuthenticatorService[IO, Int, DummyUser, Auth],
    dummyStore: BackingStore[IO, Int, DummyUser]
) {

  def embedInRequest(request: Request[IO], authenticator: Auth): Request[IO]

  def expireAuthenticator(b: Auth): IO[Auth]

  def timeoutAuthenticator(b: Auth): IO[Auth]

  def wrongKeyAuthenticator: IO[Auth]
}

abstract class AuthenticatorSpec extends TestSpec with MustMatchers with PropertyChecks with BeforeAndAfterEach {

  implicit val genDummy: Arbitrary[DummyUser] = Arbitrary(for {
    i <- Gen.chooseNum[Int](0, Int.MaxValue)
    s <- Gen.alphaNumStr
  } yield DummyUser(i, s))

  def dummyBackingStore[F[_], I, V](getId: V => I)(implicit F: MonadError[F, Throwable]) = new BackingStore[F, I, V] {
    val storageMap = mutable.HashMap.empty[I, V]

    def put(elem: V): F[V] = {
      storageMap.put(getId(elem), elem)
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

  def AuthenticatorTest[A](title: String, authSpec: AuthSpecTester[A]) = {
    behavior of title

    it should "Create, embed and extract properly" in {
      forAll { (dummy1: DummyUser) =>
        val results = (for {
          _           <- OptionT.liftF(authSpec.dummyStore.put(dummy1))
          auth        <- OptionT.liftF(authSpec.auth.create(dummy1.id))
          fromRequest <- authSpec.auth.extractAndValidate(authSpec.embedInRequest(Request[IO](), auth))
          _           <- OptionT.liftF(authSpec.dummyStore.delete(dummy1.id))
        } yield fromRequest)
          .handleErrorWith(_ => OptionT.none)
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
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe false
      }
    }

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
          .handleErrorWith(_ => OptionT.none)
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
          .handleErrorWith(_ => OptionT.none)
          .value
        val extracted = results.unsafeRunSync()
        extracted.isEmpty mustBe true
      }
    }
  }

}
