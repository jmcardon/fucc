---
layout: docs
number: 11
title: "CSRF prevention"
---

# CSRF Prevention

[CSRF](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) attacks have been losing popularity over
the past years, but they are still a possible way your application security can suffer.
If you are using any cookie-based authentication, or any sort of authentication
wherein you are _not_ sending your authentication in a custom header, this concerns you.

Fortunately, TSec provides a simple CSRF prevention middleware.

In short, to guard against this vulnerability, all you need to do is use the middleware to set the token cookie, and
send such a token along with a custom header value. Given that an attacker forging a request cannot access the values
of a cookie due to same-origin policy, this simple mechanism will guard against `CSRF`.

With good application design, you should only need to
 guard your [unsafe methods](http://restcookbook.com/HTTP%20Methods/idempotency/),
aka any http methods that could possibly make any changes to data or alter state, as this is what a
CSRF attacker is after. The `validate` method takes a
predicate `Request[F] => Boolean`, which defaults to `_.methods.isSafe`. Any action which results in `true` for
the predicate will skip the csrf check, and embed a new token if there isn't one. It is highly recommended you
leave the predicate as is, unless you _must_ make exceptions for specific routes that should be csrf-check free.

I.e If you mutate in a `GET` request (god forbid), you might want to alter the predicate to csrf check `GET`s as well.

Please, however, follow proper design principles, and keep idempotent methods idempotent.

All you need to use the CSRF middleware for tsec is:

* An `F: Sync`
* Choose between one of HMACSHA1, HMACSHA256, HMACSHA384 or HMACSHA512. **Recommended default: HMACSHA1, or 256**.
* A MacSigningKey
* An endpoint where you can give a token to a user, either by default using `withNewToken` or directly into the response
using `embed`
* (Optional) A condition which does not csrf-validate requests that cause it to be true.


A truncated signature of the class looks like this:
```scala
final class TSecCSRF[F[_], A: MacTag: ByteEV] private[tsec] (
    key: MacSigningKey[A],
    val headerName: String,
    val cookieName: String,
    val tokenLength: Int,
    clock: Clock
)
```

The `apply` method on this new class is of type:

```scala
type CSRFMiddleware[F[_]] =
    Middleware[({type T[A] = OptionT[F, A]})#T, Request[F], Response[F], Request[F], Response[F]]
```

Thus, you can use it as such:

```tut:book
import cats._
import cats.implicits._
import cats.effect.IO
import tsec.mac.jca._
import tsec.csrf.TSecCSRF
import org.http4s._
import org.http4s.dsl.io._
val newKey = HMACSHA256.unsafeGenerateKey
val tsecCSRF = TSecCSRF[IO, HMACSHA256](newKey)

val baseService: HttpRoutes[IO] = {
  HttpRoutes.of[IO] {
    case GET -> Root =>
      Ok()
  }
}

// This endpoint now provides a user with a new csrf token.
val dummyService: HttpRoutes[IO] = tsecCSRF.withNewToken(baseService)

//This endpoint is csrf checked
val dummyServiceChecked: HttpRoutes[IO] = tsecCSRF.validate()(baseService)
```