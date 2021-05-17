package tsec

import java.security.MessageDigest

import cats.effect.IO
import tsec.common._
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.jca._
import cats.effect.unsafe.implicits.global

class MacTests extends TestSpec {

  def macTest[A](
      implicit keyGen: SymmetricKeyGen[IO, A, MacSigningKey],
      pureinstance: JCAMessageAuth[IO, A]
  ): Unit = {
    behavior of pureinstance.algorithm

    //Todo: Should be with scalacheck
    it should "Sign then verify the same encrypted data properly" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k        <- keyGen.generateKey
        signed   <- pureinstance.sign(dataToSign, k)
        verified <- pureinstance.verifyBool(dataToSign, signed, k)
      } yield verified

      res.unsafeRunSync() mustBe true
    }

    it should "sign to the same message" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: IO[Boolean] = for {
        k       <- keyGen.generateKey
        signed1 <- pureinstance.sign(dataToSign, k)
        signed2 <- pureinstance.sign(dataToSign, k)
      } yield MessageDigest.isEqual(signed1, signed2)
      res.unsafeRunSync() mustBe true
    }

    it should "not verify for different messages" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes
      val incorrect  = "hello my kekistanis".utf8Bytes

      val res = for {
        k       <- keyGen.generateKey
        signed1 <- pureinstance.sign(dataToSign, k)
        cond    <- pureinstance.verifyBool(incorrect, signed1, k)
      } yield cond

      res.unsafeRunSync() mustBe false
    }

    it should "not verify for different keys" in {

      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k       <- keyGen.generateKey
        k2      <- keyGen.generateKey
        signed1 <- pureinstance.sign(dataToSign, k)
        cond    <- pureinstance.verifyBool(dataToSign, signed1, k2)
      } yield cond

      res.unsafeRunSync() mustBe false

    }
  }

  macTest[HMACSHA1]
  macTest[HMACSHA256]
  macTest[HMACSHA384]
  macTest[HMACSHA512]

}
