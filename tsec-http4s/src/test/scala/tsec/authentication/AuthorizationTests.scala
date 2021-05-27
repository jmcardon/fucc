package tsec.authentication

import cats.effect.IO
import cats.implicits._
import org.http4s.Request
import org.scalatest.matchers.should.Matchers._
import tsec.TestSpec
import tsec.authentication.DummyRole.{Admin, Other}
import tsec.authorization._

final case class AuthDummyUser(id: Int, role: DummyRole, authLevel: AuthLevel = AuthLevel.CEO)

object AuthDummyUser {
  implicit val authInfo1: AuthorizationInfo[IO, DummyRole, AuthDummyUser] =
    new AuthorizationInfo[IO, DummyRole, AuthDummyUser] {
      def fetchInfo(u: AuthDummyUser): IO[DummyRole] = IO.pure(u.role)
    }

  implicit val authInfo2: AuthorizationInfo[IO, AuthLevel, AuthDummyUser] =
    new AuthorizationInfo[IO, AuthLevel, AuthDummyUser] {
      def fetchInfo(u: AuthDummyUser): IO[AuthLevel] = IO.pure(u.authLevel)
    }
}

sealed abstract case class AuthLevel(i: Int)
object AuthLevel extends SimpleAuthEnum[AuthLevel, Int] {
  val CEO: AuthLevel           = new AuthLevel(0) {}
  val Staff: AuthLevel         = new AuthLevel(1) {}
  val AugmentedUser: AuthLevel = new AuthLevel(2) {}
  val RegularUser: AuthLevel   = new AuthLevel(3) {}

  def getRepr(t: AuthLevel): Int = t.i

  protected val values: AuthGroup[AuthLevel] = AuthGroup(CEO, Staff, AugmentedUser, RegularUser)
}

class AuthorizationTests extends TestSpec {

  val basicRBAC = BasicRBAC[IO, DummyRole, AuthDummyUser, Int](Admin, Other)

  val dummyRequest = Request[IO]()

  behavior of "BasicRBAC"

  it should "let a request pass through if in group" in {
    val dummySreq = SecuredRequest[IO, AuthDummyUser, Int](dummyRequest, AuthDummyUser(0, Admin), 0)
    basicRBAC.isAuthorized(dummySreq).value.unsafeRunSync() mustBe Some(dummySreq)
  }

  it should "not let a request pass through if not contained" in {
    val dummySreq = SecuredRequest[IO, AuthDummyUser, Int](dummyRequest, AuthDummyUser(0, DummyRole.User), 0)
    basicRBAC.isAuthorized(dummySreq).value.unsafeRunSync() mustBe None
  }

  behavior of "BasicDAC"

  val basicDAC = new BasicDAC[IO, Int, AuthDummyUser, Int] {
    def fetchGroup: IO[AuthGroup[Int]] = IO.pure(AuthGroup(4, 5, 6))

    def fetchOwner: IO[Int] = IO.pure(1)

    def fetchAccess(u: SecuredRequest[IO, AuthDummyUser, Int]): IO[Int] = IO.pure(u.identity.id)
  }

  it should "let a request pass if owner but not in group" in {
    val dummySreq = SecuredRequest[IO, AuthDummyUser, Int](dummyRequest, AuthDummyUser(1, DummyRole.User), 0)
    basicDAC.isAuthorized(dummySreq).value.unsafeRunSync() mustBe Some(dummySreq)
  }

  it should "let a request pass if in group but not owner" in {
    val dummySreq = SecuredRequest[IO, AuthDummyUser, Int](dummyRequest, AuthDummyUser(4, DummyRole.User), 0)
    basicDAC.isAuthorized(dummySreq).value.unsafeRunSync() mustBe Some(dummySreq)
  }

  it should "not let the request pass if in neither" in {
    val dummySreq = SecuredRequest[IO, AuthDummyUser, Int](dummyRequest, AuthDummyUser(14, DummyRole.User), 0)
    basicDAC.isAuthorized(dummySreq).value.unsafeRunSync() mustBe None
  }

  behavior of "HierarchyAuth"

  implicit val authInfo: AuthorizationInfo[IO, AuthLevel, AuthLevel] = new AuthorizationInfo[IO, AuthLevel, AuthLevel] {
    def fetchInfo(u: AuthLevel): IO[AuthLevel] = IO.pure(u)
  }

  val hierarchyAuth = HierarchyAuth[IO, AuthLevel, AuthLevel, Int](AuthLevel.Staff).unsafeRunSync()

  it should "let a user with lower than the required clearance pass" in {
    val dummySReq = SecuredRequest[IO, AuthLevel, Int](dummyRequest, AuthLevel.CEO, 0)
    hierarchyAuth.isAuthorized(dummySReq).value.unsafeRunSync() mustBe Some(dummySReq)
  }

  it should "let a user with equal clearance pass" in {
    val dummySReq = SecuredRequest[IO, AuthLevel, Int](dummyRequest, AuthLevel.Staff, 0)
    hierarchyAuth.isAuthorized(dummySReq).value.unsafeRunSync() mustBe Some(dummySReq)
  }

  it should "not a user with equal clearance pass" in {
    val dummySReq = SecuredRequest[IO, AuthLevel, Int](dummyRequest, AuthLevel.AugmentedUser, 0)
    hierarchyAuth.isAuthorized(dummySReq).value.unsafeRunSync() mustBe None
  }

  behavior of "DynamicRBAC"

  val dynamicAuthGroup = new DynamicAuthGroup[IO, DummyRole] {
    def fetchGroupInfo: IO[AuthGroup[DummyRole]] = IO.pure(AuthGroup(DummyRole.Admin, DummyRole.User))
  }

  val dynamicRBAC = DynamicRBAC[IO, DummyRole, AuthDummyUser, Int](dynamicAuthGroup)

  it should "let a request pass through if in group" in {
    val dummySreq = SecuredRequest[IO, AuthDummyUser, Int](dummyRequest, AuthDummyUser(0, Admin), 0)
    dynamicRBAC.isAuthorized(dummySreq).value.unsafeRunSync() mustBe Some(dummySreq)
  }

  it should "not let a request pass through if not contained" in {
    val dummySreq = SecuredRequest[IO, AuthDummyUser, Int](dummyRequest, AuthDummyUser(0, DummyRole.User), 0)
    dynamicRBAC.isAuthorized(dummySreq).value.unsafeRunSync() mustBe None
  }

  behavior of "Bell La Padula"
  val readAction  = BLPReadAction[IO, AuthLevel, AuthDummyUser, Int](AuthLevel.Staff).unsafeRunSync()
  val writeAction = BLPWriteAction[IO, AuthLevel, AuthDummyUser, Int](AuthLevel.Staff).unsafeRunSync()

  it should "read same level" in {
    val dummySReq = SecuredRequest(dummyRequest, AuthDummyUser(0, DummyRole.Admin, AuthLevel.Staff), 0)
    readAction.isAuthorized(dummySReq).value.unsafeRunSync() mustBe Some(dummySReq)
  }

  it should "read lower level" in {
    val dummySReq = SecuredRequest(dummyRequest, AuthDummyUser(0, DummyRole.Admin, AuthLevel.Staff), 0)
    (for {
      ra <- BLPReadAction[IO, AuthLevel, AuthDummyUser, Int](AuthLevel.RegularUser)
      r  <- ra.isAuthorized(dummySReq).value
    } yield r).unsafeRunSync() mustBe Some(dummySReq)
  }
  it should "not read up" in {
    val dummySReq = SecuredRequest(dummyRequest, AuthDummyUser(0, DummyRole.Admin, AuthLevel.AugmentedUser), 0)
    readAction.isAuthorized(dummySReq).value.unsafeRunSync() mustBe None
  }

  it should "only write same level" in {
    val dummySReq = SecuredRequest(dummyRequest, AuthDummyUser(0, DummyRole.Admin, AuthLevel.Staff), 0)
    (for {
      r1 <- writeAction.isAuthorized(dummySReq).value
      r2 <- writeAction
        .isAuthorized(SecuredRequest(dummyRequest, AuthDummyUser(0, DummyRole.Admin, AuthLevel.CEO), 0))
        .value
      r3 <- writeAction
        .isAuthorized(SecuredRequest(dummyRequest, AuthDummyUser(0, DummyRole.Admin, AuthLevel.AugmentedUser), 0))
        .value
    } yield (r1, r2, r3)).unsafeRunSync() mustBe ((Some(dummySReq), None, None))
  }

}
