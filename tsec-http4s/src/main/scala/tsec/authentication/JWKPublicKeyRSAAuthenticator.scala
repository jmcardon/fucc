package tsec.authentication

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.time.Instant

import cats.data.OptionT
import cats.effect.{Effect, Sync}
import cats.syntax.all._
import fs2.async.Ref
import io.circe.Decoder
import io.circe.generic.auto._
import io.circe.parser.decode
import org.http4s.circe._
import org.http4s.client.Client
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Credentials, EntityDecoder, Request, Response, Uri}
import tsec.common.{SecureRandomId, _}
import tsec.jws.signature.{JWSSigCV, JWTSig}
import tsec.signature.jca.{JCASigTag, RSAKFTag, SigPublicKey}

import scala.concurrent.duration.FiniteDuration

final case class AugmentedJWK[A, I](
    id: SecureRandomId,
    jwt: JWTSig[A],
    identity: I,
    expiry: Instant,
    lastTouched: Option[Instant]
)

final case class Modulus(value: BigInt) extends AnyVal
final case class Exponent(value: BigInt) extends AnyVal
final case class JWK[A](kid: String, kty: String, use: String, x5c: List[SigPublicKey[A]], n: Modulus, e: Exponent)

final case class JWKS[A](keys: List[JWK[A]])

class KeyRegistry[F[_], A: JCASigTag: RSAKFTag](
   uri: Uri,
   minFetchDelay: FiniteDuration,
   keys: Ref[F, Map[String, SigPublicKey[A]]],
   lastFetch: Ref[F, Instant],
   client: Client[F]
)(implicit E: Effect[F]) {

  implicit val jwksDecoder: EntityDecoder[F, JWKS[A]] = jsonOf[F, JWKS[A]]
  implicit val modulusDecoder: Decoder[Modulus]       = Decoder.decodeString.map(s => Modulus(BigInt(1, s.base64UrlBytes)))
  implicit val exponentDecoder: Decoder[Exponent]     = Decoder.decodeString.map(s => Exponent(BigInt(1, s.base64UrlBytes)))
  implicit val x5cDecoder: Decoder[SigPublicKey[A]]   = Decoder.decodeString.map(s => {
    val cf = CertificateFactory.getInstance("X.509")
    val cert = cf.generateCertificate(new ByteArrayInputStream(s.base64Bytes))
    SigPublicKey[A](cert.getPublicKey)
  })

  def getPublicKey(id: String): F[Option[SigPublicKey[A]]] =
    getKey(id).flatMap {
      case None => shouldFetch().flatMap {
        case true =>
          for {
            jwks <- client.expect[JWKS[A]](uri)
            k    <- E.delay(jwks.keys.map(jwk => (jwk.kid, jwk.x5c.head)).toMap)
            _    <- keys.setSync(k)
            now  <- E.delay(Instant.now())
            _    <- lastFetch.setSync(now)
            key  <- E.delay(k.get(id))
          } yield key
        case false => none[SigPublicKey[A]].pure[F]
      }
      case r => r.pure
    }

  private def shouldFetch() = for {
    lf  <- lastFetch.get
    now <- E.delay(Instant.now())
    b   <- lf.isBefore(now.minusSeconds(minFetchDelay.toSeconds)).pure
  } yield b

  private def getKey(id: String) = keys.get.map(_.get(id))

}

class JWKPublicKeyRSAAuthenticator[F[_] : Effect, I: Decoder, V, A: JCASigTag: RSAKFTag](
   expiryDuration: FiniteDuration,
   maxIdleDuration: Option[FiniteDuration],
   identityStore: IdentityStore[F, I, V],
   keyRegistry: KeyRegistry[F, A]
)(implicit cv: JWSSigCV[F, A]) extends Authenticator[F, I, V, AugmentedJWK[A, I]] {

  override def expiry: FiniteDuration = expiryDuration

  override def maxIdle: Option[FiniteDuration] = None

  /** Attempt to retrieve the raw representation of an A
    * This is primarily useful when attempting to combine AuthenticatorService,
    * to be able to evaluate an endpoint with more than one token type.
    * or simply just to prod whether the request is malformed.
    *
    * @return
    */
  override def extractRawOption(request: Request[F]): Option[String] =
    request.headers.get(Authorization).flatMap { t =>
      t.credentials match {
        case Credentials.Token(scheme, token) if scheme == AuthScheme.Bearer =>
          Some(token)
        case _ => None
      }
    }

  /** Parse the raw representation from `extractRawOption`
    *
    */
  override def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AugmentedJWK[A, I]]] =
    OptionT(
      (for {
        now          <- Sync[F].delay(Instant.now())
        extractedRaw <- cv.extractRaw(raw)
        publicKey    <- keyRegistry.getPublicKey(extractedRaw.header.kid.get)
        extracted    <- cv.verify(raw, publicKey.get, now)
        jwtid        <- cataOption(extracted.body.subject)
        id           <- cataOption(extracted.body.subject.flatMap(decode[I](_).toOption))
        expiry       <- cataOption(extracted.body.expiration)
        augmented = AugmentedJWK(
          SecureRandomId.coerce(jwtid),
          extracted,
          id,
          expiry,
          None
        )
        identity <- identityStore.get(id).orAuthFailure
      } yield SecuredRequest(request, identity, augmented).some)
        .handleError(_ => None)
    )

  /** Create an authenticator from an identifier.
    *
    * @param body
    * @return
    */
  override def create(body: I): F[AugmentedJWK[A, I]] =
    Sync[F].raiseError(new Exception("A JWKSAuthenticator cannot create an authenticator as it has no access to the private key"))

  /** Update the altered authenticator
    *
    * @param authenticator
    * @return
    */
  override def update(authenticator: AugmentedJWK[A, I]): F[AugmentedJWK[A, I]] = authenticator.pure[F]

  /** Delete an authenticator from a backing store, or invalidate it.
    *
    * @param authenticator
    * @return
    */
  override def discard(authenticator: AugmentedJWK[A, I]): F[AugmentedJWK[A, I]] = authenticator.pure[F]

  /** Renew an authenticator: Reset it's expiry and whatnot.
    *
    * @param authenticator
    * @return
    */
  override def renew(authenticator: AugmentedJWK[A, I]): F[AugmentedJWK[A, I]] = authenticator.pure[F]

  /** Refresh an authenticator: Primarily used for sliding window expiration
    *
    * @param authenticator
    * @return
    */
  override def refresh(authenticator: AugmentedJWK[A, I]): F[AugmentedJWK[A, I]] = authenticator.pure[F]

  /** Embed an authenticator directly into a response.
    * Particularly useful for adding an authenticator into unauthenticated actions
    *
    * @param response
    * @return
    */
  override def embed(response: Response[F], authenticator: AugmentedJWK[A, I]): Response[F] = response

  /** Handles the embedding of the authenticator (if necessary) in the response,
    * and any other actions that should happen after a request related to authenticators
    *
    * @param response
    * @param authenticator
    * @return
    */
  override def afterBlock(response: Response[F], authenticator: AugmentedJWK[A, I]): OptionT[F, Response[F]] =
    OptionT.pure[F](embed(response, authenticator))

}
