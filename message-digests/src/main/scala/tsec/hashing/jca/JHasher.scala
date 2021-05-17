package tsec.hashing.jca

import java.security.MessageDigest

import cats.Applicative
import fs2.{Chunk, Pipe, Stream}
import tsec.hashing.{CryptoHash, CryptoHasher}

final class JHasher[F[_], A] private[jca] (val algorithm: String)(
    implicit F: Applicative[F]
) extends CryptoHasher[F, A] {

  private def genInstance = MessageDigest.getInstance(algorithm)

  def hash(bytes: Array[Byte]): F[CryptoHash[A]] =
    F.pure(CryptoHash[A](genInstance.digest(bytes)))

  /** In this case, we use the same code as fs2, but we resolve
    * the hash string prefix from the implicit
    */
  def hashPipe: Pipe[F, Byte, Byte] =
    in =>
      Stream.suspend[F, Byte] {
        in.chunks
          .fold(genInstance) { (d, c) =>
            val bytes = c.toArray
            d.update(bytes, 0, bytes.size)
            d
          }
          .flatMap { d =>
            Stream.chunk(Chunk.array(d.digest()))
          }
    }
}
