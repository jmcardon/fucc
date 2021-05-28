# Service Composition

Tsec provides ways to leverage Authentication, and Authorization to your endpoints. This means that for one route your could have endpoints with different authentication/authorization mechanisms.

For instance, let's say we have an `item` route with three different endpoints, each one having different security mechanisms :
```
GET /api/v1/items    -> unauthenticated:              everyone on the internet can get items.
PUT /api/v1/items    -> authenticated:                only logged in users can create new items.
DELETE /api/v1/items -> authenticated and authorized: only logged in admins can delete items.
```

So what we want to achieve is to expose these endpoints with Http4s within a single route. Let's do that.


### Preparation
I the following example we will use the BearerToken authentication mechanism.
Let's go through the ServiceCompositionExample and ServiceCompositionTest classes step-by-step:

First, let's create some users and obtain there authentication tokens:
```tut

import cats.effect.IO
import cats.implicits._
import http4sExamples.BearerTokenExample.{Auth, userStore}
import http4sExamples.ExampleAuthHelpers.{Role, User}
import org.http4s.implicits._
import org.http4s.{HttpRoutes, Response, Status}
import org.http4s.dsl.io.{->, /, DELETE, GET, PUT, Root}
import tsec.authentication.{SecuredRequest, TSecAuthService, TSecBearerToken, asAuthed}
import tsec.authorization.BasicRBAC 

  // Create users
  val adminUser: User = User(0, 18, "admin", Role.Administrator)
  val customerUser: User = User(1, 15, "user", Role.Customer)

  // Store them
  userStore.put(adminUser).unsafeRunSync()
  userStore.put(customerUser).unsafeRunSync()

  // Create Tokens
  val adminToken = Auth.authenticator.create(adminUser.id).unsafeRunSync()
  val userToken = Auth.authenticator.create(customerUser.id).unsafeRunSync()

  // Set Authorization policy
  val rbacPolicy = BasicRBAC[IO, Role, User, TSecBearerToken[Int]](Role.Administrator)
```

Now let's define and compose our services. The first approach could be to define one service for each endpoint and compose them together as usual.

```tut
  val deleteItem = Auth.liftService(TSecAuthService.withAuthorization(rbacPolicy) {
      case DELETE -> Root / "items" asAuthed adminUser => IO(Response(status = Status.NoContent))
    })

  val putItem =
    Auth.liftService(TSecAuthService {
      case PUT -> Root / "items" asAuthed user => IO(Response(status = Status.Created))
    })

  val getItem = HttpRoutes.of[IO] {
    case GET -> Root / "items" => IO(Response(status = Status.Ok))
  }

  // Service composition
  val securedService = deleteItem <+> putItem <+> getItem
  val myApp = securedService.orNotFound
```
Everything looks good, let's test our composed service:

``` 
import cats.effect.IO
import http4sExamples.ServiceCompositionExample._
import org.http4s.implicits._
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, Http4sLiteralSyntax, Method, Request, Status, Uri}
import tsec.TestSpec

class ServiceCompositionTest extends TestSpec {
  val getReq = Request[IO](method = Method.GET, uri = uri"items")
  val putReq = Request[IO](method = Method.PUT, uri = uri"items")
    .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, userToken.id)))
  val delReq = Request[IO](method = Method.DELETE, uri = uri"items")
    .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, adminToken.id)))

  myApp.run(getReq).unsafeRunSync().status mustBe Status.Ok
  myApp.run(putReq).unsafeRunSync().status mustBe Status.Created
  myApp.run(delReq).unsafeRunSync().status mustBe Status.NoContent
}
```

_Running the test fails_:   
* The access to the `GET` endpoint is denied saying the user is not authorized with `HTTP 401`. Let's try to change the service composition order, putting the getItem service first:
```
val securedService = getItem <+> deleteItem <+> putItem
``` 
The `GET` succeeds, but now ...
* The `PUT` fails with a `HTTP 401`. Let's now change the service composition order to ```val securedService = getItem <+> putItem <+> deleteItem```. Now the test for the `PUT` endpoint is a success, but the test for the `DELETE` endpoint fails with `HTTP 404`.

### Insights

From there we can make a *guess* about service composition behavior:
* unsecured services let requests pass through other services down the chain.
* services that requires authentication don't let requests pass through other services down the chain throwing a `HTTP 404`.
* services that both require authentication and authorization don't let requests pass through other services down the chain throwing a `HTTP 401`.

Looking at the implementation of the `TSecAuthService` we can see that:
* A `TSecAuthService` can be seen as a function that applies the endpoint logic to the SecuredRequest.
* This function application can be constrained by an authorization mechanisms with the `withAuthorization` method. We can also provide a fallback if the authorization fails with the `withAuthorizationHandler` method.

And looking at the implementation of the `SecuredRequestHandler`:
* The `SecuredRequestHandler` lifts this a `TSecAuthService` into an `HttpRoute` through a `TSecMiddleware` that checks whether the user is authenticated or not.
* `SecuredRequestHandler` also provides a fall through mechanisms when the user is not authenticated.

Now let's try to leverage the fall-through mechanisms at our disposal. We can see that `TSecAuthService.withAuthorizationHandler` accepts a function of type `SecuredRequest[F, I, A] => OptionT[F, Response[F]]`, which is basically a `TSecAuthService`! That's what we'll provide.

### Rework
We will first strip down our endpoint logic to PartialFunction, because we saw that's what `TSecAuthService` eats.
```tut
  type PartialEndpoint = PartialFunction[SecuredRequest[IO, User, TSecBearerToken[Int]], IO[Response[IO]]]
  
val deleteItem: PartialEndpoint = {
    case DELETE -> Root / "items" asAuthed _ => IO(Response(status = Status.NoContent))
  }

  val putItem: PartialEndpoint = {
    case PUT -> Root / "items" asAuthed _ => IO(Response(status = Status.Created))
  }

  val getItem = HttpRoutes.of[IO] {
    case GET -> Root / "items" => IO(Response(status = Status.Ok))
  }
```
And now we can now try to create and compose our services in order for our three requests to succeed. 
We first put the unauthenticated endpoint, so unauthenticated users can reach it. Then we combine it with our second service. 
This second service will first serve authorized users, and then (if user is not authorized) fall through an authenticated service.  

```tut
 val securedService = getItem <+> Auth.liftService(TSecAuthService.withAuthorizationHandler(rbacPolicy)(deleteItem, TSecAuthService(putItem).run))
```

If we run the tests, then you should see your three requests pass.

### And finally

We can now re-write our three assumptions defined earlier and use those as rule of thumbs when composing services:
* unsecured services let requests pass through other services down the chain.
* services that requires authentication, have a fallthrough mechanism is case of failed authentication.
* services that bot requires authentication and Authorization, have a fall-through mechanism when authenticated users authorization fails.


### Going further:
We're nearly done. Let's just check what an unauthenticated user sees when he wants to reach authenticated/authorized endpoints

```
val putReqUnAuth = Request[IO](method = Method.PUT, uri = uri"items")
val delReqUnAuth = Request[IO](method = Method.DELETE, uri = uri"items")

myApp.run(putReqUnAuth).unsafeRunSync().status mustBe Status.Unauthorized
myApp.run(delReqUnAuth).unsafeRunSync().status mustBe Status.Unauthorized

val delReqUnauth2 = Request[IO](method = Method.DELETE, uri = uri"items")
  .putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, userToken.id)))
myApp.run(delReqUnauth2).unsafeRunSync().status mustBe Status.NotFound
```
The tests pass, but here we can see that we are leaking the fact that admin endpoints do exist for unauthenticated users (second statement). A best practice is to hide the fact that admin endpoints do exist as described [here](https://developer.github.com/v3/troubleshooting/#why-am-i-getting-a-404-error-on-a-repository-that-exists).

Let's try to code a combination that does the trick:
```
val securedService = getItem <+> Auth.liftWithFallthrough(
   TSecAuthService(putItem),
   Auth.liftService(TSecAuthService.withAuthorization(rbacPolicy)(deleteItem)).orNotFound.run)
```
In this case though, we will never reach the `deleteItem` endpoint. This is because the fall through mechanism will be active in case of failed authentication only.  Here our authentication is successful, but the endpoint is not found in the `TSecAuthService(putItem)` service, hence `HTTP 404`. So the following composition `unauthenticated <+> authenticated <+> authorized` cannot be achieved.  There is a little room for improvement.
