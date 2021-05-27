package tsec

import cats.data.OptionT
import org.bouncycastle.util.encoders.Hex
import org.http4s.server.Middleware
import org.http4s.{Request, Response}
import tsec.common.ManagedRandom

package object csrf {

  type CSRFToken = CSRFToken.Token

  object CSRFToken extends ManagedRandom {
    type Token <: String

    def apply(s: String): CSRFToken   = s.asInstanceOf[CSRFToken]
    def subst[F[_]](value: F[String]): F[CSRFToken] = value.asInstanceOf[F[CSRFToken]]

    def generateHexBase(tokenLength: Int = 32): String = {
      val tokenBytes = new Array[Byte](tokenLength)
      nextBytes(tokenBytes)
      Hex.toHexString(tokenBytes)
    }
  }

  type CSRFMiddleware[F[_]] =
    Middleware[({type T[A] = OptionT[F, A]})#T, Request[F], Response[F], Request[F], Response[F]]


}
