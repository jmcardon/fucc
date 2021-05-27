package tsec

import cats.effect.IO
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.jca._
import tsec.common._
import tsec.cookies.AEADCookieEncryptor
import tsec.keygen.symmetric.SymmetricKeyGen

class AEADCookieSignerTest extends TestSpec {

  def aeadCookieTest[A](implicit api: AESGCM[A], keyGen: SymmetricKeyGen[IO, A, SecretKey]): Unit = {
    implicit val strategy : IvGen[IO, A] = api.defaultIvStrategy[IO]

    implicit val instance: AADEncryptor[IO, A, SecretKey] = api.genEncryptor[IO]

    behavior of s"AEAD Cookie encrypting with ${api.cipherName}${api.keySizeBytes * 8}"

    it should "Encrypt and decrypt properly" in {
      val now = java.time.Instant.now().toString
      forAll { (s: String) =>
        val encryptDecrypt = for {
          key       <- keyGen.generateKey
          encrypted <- AEADCookieEncryptor.signAndEncrypt[IO, A](s, AAD(now.utf8Bytes), key)
          decrypted <- AEADCookieEncryptor.retrieveFromSigned[IO, A](encrypted, key)
        } yield decrypted

        if (s.isEmpty)
          encryptDecrypt.attempt.unsafeRunSync() mustBe Left(EncryptError("Cannot encrypt an empty string!"))
        else
          encryptDecrypt.attempt.unsafeRunSync() mustBe Right(s)
      }
    }

    it should "not encrypt and decrypt properly with an incorrect key" in {
      val now = java.time.Instant.now().toString
      forAll { (s: String) =>
        val encryptDecrypt = for {
          key       <- keyGen.generateKey
          key2      <- keyGen.generateKey
          encrypted <- AEADCookieEncryptor.signAndEncrypt[IO, A](s, AAD(now.utf8Bytes), key)
          decrypted <- AEADCookieEncryptor.retrieveFromSigned[IO, A](encrypted, key2)
        } yield decrypted

        if (s.isEmpty)
          encryptDecrypt.attempt.unsafeRunSync() mustBe Left(EncryptError("Cannot encrypt an empty string!"))
        else
          encryptDecrypt.attempt.unsafeRunSync() mustBe a[Left[CipherError, _]]
      }
    }
  }

  aeadCookieTest[AES128GCM]
  aeadCookieTest[AES192GCM]
  aeadCookieTest[AES256GCM]
}
