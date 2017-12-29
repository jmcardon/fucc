package tsec

import java.util.concurrent.TimeUnit
import javax.crypto
import javax.crypto.Cipher

import cats.effect.IO
import org.openjdk.jmh.annotations._
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric.imports._
import tsec.cipher.symmetric.imports.aead._
import tsec.cipher.symmetric.{PlainText => OPlainText, _}
import tsec.common._
import tsec.libsodium._
import tsec.libsodium.cipher._
import tsec.libsodium.cipher.aead.AES256GCM

import scala.util.Random

@State(Scope.Thread)
@BenchmarkMode(Array(Mode.Throughput))
@OutputTimeUnit(TimeUnit.MILLISECONDS)
class CipherBench {

  /** Our libsodium setup **/
  implicit lazy val sodium: ScalaSodium            = ScalaSodium.getSodiumUnsafe
  lazy val chachaKey: SodiumKey[XChacha20Poly1305] = XChacha20Poly1305.generateKeyUnsafe
  lazy val sodiumAESKey: SodiumKey[AES256GCM]      = AES256GCM.generateKeyUnsafe

  /** AES using tsec classes **/
  lazy val jcaAESKey: SecretKey[AES256]                    = AES256.generateKeyUnsafe()
  lazy val jcaAES: JCAAEAD[IO, AES256, GCM, NoPadding] = JCAAEAD[IO, AES256, GCM, NoPadding]().unsafeRunSync()

  /** Our AES using the JCA raw classes. Note: We reuse cipher the instance for speed, but it's not thread safe **/
  lazy val jcaRAWKey: crypto.SecretKey = SecretKey.toJavaKey(AES256.generateKeyUnsafe())
  lazy val jcaRAWInstance: Cipher      = Cipher.getInstance("AES/GCM/NoPadding")

  /** Our random plaintext **/
  lazy val longPlaintext: OPlainText = OPlainText(Array.fill[Char](5000)(Random.nextInt(127).toChar).mkString.utf8Bytes)
  lazy val nPlaintext: PlainText = PlainText(longPlaintext.content)

  @Benchmark
  def testJCARawSideEffecting(): Any = {
    jcaRAWInstance.init(Cipher.ENCRYPT_MODE, jcaRAWKey)
    jcaRAWInstance.doFinal(longPlaintext.content)
  }

  @Benchmark
  def testJCARawCreateInstance(): Any = {
    val j = Cipher.getInstance("AES/GCM/NoPadding")
    j.init(Cipher.ENCRYPT_MODE, jcaRAWKey)
    j.doFinal(longPlaintext.content)
  }

  /** We test each io action
    * to view the related overhead, but we do not care about sequencing them
    */
  @Benchmark
  def testTSecJCA(): Any =
    jcaAES
      .encrypt(longPlaintext, jcaAESKey)
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumAES(): Any =
    AES256GCM
      .encrypt[IO](nPlaintext, sodiumAESKey)
      .unsafeRunSync()

  @Benchmark
  def testLibSodiumXChacha20(): Any =
    XChacha20Poly1305
      .encrypt[IO](nPlaintext, chachaKey)
      .unsafeRunSync()

}
