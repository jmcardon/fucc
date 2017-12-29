package tsec.libsodium

import cats.effect.IO
import tsec.common._
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.aead._
import tsec.libsodium.cipher.internal.SodiumAEADPlatform

class SodiumAEADTest extends SodiumSpec {

  def testAEAD[A](p: SodiumAEADPlatform[A]) = {
    behavior of s"${p.algorithm} aead"

    it should "generate key, encrypt and decrypt properly" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          encrypt <- p.encrypt[IO](pt, key)
          decrypt <- p.decrypt[IO](encrypt, key)
        } yield decrypt
        if (!s.isEmpty)
          program.unsafeRunSync().toHexString mustBe pt.toHexString
      }
    }

    it should "not decrypt properly for a wrong key" in {
      forAll { (s: String) =>
        val pt = PlainText(s.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key     <- p.generateKey[IO]
            key2    <- p.generateKey[IO]
            encrypt <- p.encrypt[IO](pt, key)
            decrypt <- p.decrypt[IO](encrypt, key2)
          } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "generate key, encrypt and decrypt properly for aad" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = SodiumAAD(aad.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          encrypt <- p.encryptAAD[IO](pt, key, saad)
          decrypt <- p.decryptAAD[IO](encrypt, key, saad)
        } yield decrypt
        program.unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "not decrypt properly for a wrong key, but correct AAD" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = SodiumAAD(aad.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          key2    <- p.generateKey[IO]
          encrypt <- p.encryptAAD[IO](pt, key, saad)
          decrypt <- p.decryptAAD[IO](encrypt, key2, saad)
        } yield decrypt
        program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "only decrypt properly for the same aad" in {
      forAll { (s: String, aad: String, aad2: String) =>
        val pt    = PlainText(s.utf8Bytes)
        val saad  = SodiumAAD(aad.utf8Bytes)
        val saad2 = SodiumAAD(aad2.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          encrypt <- p.encryptAAD[IO](pt, key, saad)
          decrypt <- p.decryptAAD[IO](encrypt, key, saad2)
        } yield decrypt
        if (aad != aad2)
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
        else
          program.unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "encrypt and decrypt properly with a split tag" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = SodiumAAD(aad.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key           <- p.generateKey[IO]
            encryptedPair <- p.encryptAADDetached[IO](pt, key, saad)
            decrypt       <- p.decryptAADDetached[IO](encryptedPair._1, key, encryptedPair._2, saad)
          } yield decrypt).unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "not decrypt properly with an incorrect key detached" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = SodiumAAD(aad.utf8Bytes)
        if (!s.isEmpty)
          (for {
            key     <- p.generateKey[IO]
            key2    <- p.generateKey[IO]
            encrypt <- p.encryptAADDetached[IO](pt, key, saad)
            decrypt <- p.decryptAADDetached[IO](encrypt._1, key2, encrypt._2, saad)
          } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

    it should "only decrypt properly with the same key" in {
      forAll { (s: String, aad: String) =>
        val pt    = PlainText(s.utf8Bytes)
        val saad  = SodiumAAD(aad.utf8Bytes)
        val program = for {
          key     <- p.generateKey[IO]
          key2    <- p.generateKey[IO]
          encrypt <- p.encryptAADDetached[IO](pt, key, saad)
          decrypt <- p.decryptAADDetached[IO](encrypt._1, key2, encrypt._2, saad)
        } yield decrypt
        if (s.isEmpty || aad.isEmpty)
          program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
        else
          program.unsafeRunSync().toUtf8String mustBe pt.toUtf8String
      }
    }

    it should "not decrypt properly with an incorrect tag but correct key" in {
      forAll { (s: String, aad: String) =>
        val pt   = PlainText(s.utf8Bytes)
        val saad = SodiumAAD(aad.utf8Bytes)
        val program = for {
          key         <- p.generateKey[IO]
          encrypt     <- p.encryptAADDetached[IO](pt, key, saad)
          randomBytes <- ScalaSodium.randomBytes[IO](p.authTagLen)
          decrypt     <- p.decryptAADDetached[IO](encrypt._1, key, AuthTag.is[A].coerce(randomBytes), saad)
        } yield decrypt
        program.attempt.unsafeRunSync() mustBe a[Left[SodiumCipherError, _]]
      }
    }

  }

  testAEAD(XChacha20AEAD)
  testAEAD(IETFChacha20)
  testAEAD(OriginalChacha20)
  testAEAD(AES256GCM)

}
