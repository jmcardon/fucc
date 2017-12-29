package tsec.common

import java.security.SecureRandom
import java.util.concurrent.atomic.LongAdder

/** A trait that manages a secureRandom instance
  * when
  *
  */
trait ManagedRandom {

  /** Cache our random, and seed it properly as per
    * [[https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/]]
    *
    * @note Random may block on linux machines.
    */
  private[tsec] var cachedRand: SecureRandom = {
    val r = new SecureRandom()
    r.nextBytes(new Array[Byte](20))
    r
  }

  /** We will keep a reference to how many times our random is utilized
    * After a sensible Integer.MaxValue/5 times, we should reseed
    */
  private val adder: LongAdder = new LongAdder
  private val MaxBeforeReseed  = (Integer.MAX_VALUE / 5).toLong

  private def reSeed(): Unit = {
    adder.reset()
    val tmpRand = new SecureRandom()
    tmpRand.nextBytes(new Array[Byte](20))
    cachedRand = tmpRand
  }

  private[tsec] def forceIncrement(): Unit = {
    adder.increment()
    if (adder.sum() == MaxBeforeReseed)
      reSeed()
  }

  def nextBytes(bytes: Array[Byte]): Unit = {
    adder.increment()
    if (adder.sum() == MaxBeforeReseed)
      reSeed()
    cachedRand.nextBytes(bytes)
  }
}
