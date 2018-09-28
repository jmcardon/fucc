package tsec

import java.nio.charset.{Charset, StandardCharsets}

import tsec.common.TSecError

package object passwordhashers {

  type PasswordHash[A] = PasswordHash.PHash[A]

  private[tsec] val defaultCharset: Charset = StandardCharsets.UTF_8

  object PasswordHash {
    type PHash[A] <: String

    def apply[A](pw: String): PasswordHash[A] = pw.asInstanceOf[PasswordHash[A]]
    def subst[A]: PwPartiallyApplied[A]       = new PwPartiallyApplied[A]

    private[passwordhashers] final class PwPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[String]): F[PasswordHash[A]] = value.asInstanceOf[F[PasswordHash[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[PasswordHash[A]]): F[String] = value.asInstanceOf[F[String]]
    }
  }

  final case class PasswordError(cause: String) extends TSecError
}
