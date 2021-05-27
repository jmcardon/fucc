package tsec.authentication

import java.time.Instant
import java.util.UUID

import cats.data.OptionT
import cats.effect.Sync
import cats.syntax.all._
import io.circe.generic.auto._
import io.circe.parser.decode
import io.circe.syntax._
import io.circe.{Decoder, Encoder}
import org.http4s._
import tsec.cipher.symmetric.{IvGen, _}
import tsec.cipher.symmetric.jca._
import tsec.common._
import tsec.cookies._
import tsec.hashing.jca._
import tsec.jwt.JWTPrinter

import scala.concurrent.duration.FiniteDuration

sealed abstract class EncryptedCookieAuthenticator[F[_]: Sync, I, V, A]
    extends Authenticator[F, I, V, AuthEncryptedCookie[A, I]]

sealed abstract class StatefulECAuthenticator[F[_]: Sync, I, V, A] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
) extends EncryptedCookieAuthenticator[F, I, V, A] {
  def withKey(newKey: SecretKey[A]): StatefulECAuthenticator[F, I, V, A]

  def withSettings(settings: TSecCookieSettings): StatefulECAuthenticator[F, I, V, A]

  def withIdentityStore(newStore: IdentityStore[F, I, V]): StatefulECAuthenticator[F, I, V, A]

  def withTokenStore(
      newStore: BackingStore[F, UUID, AuthEncryptedCookie[A, I]]
  ): StatefulECAuthenticator[F, I, V, A]
}

sealed abstract class StatelessECAuthenticator[F[_]: Sync, I, V, A] private[tsec] (
    val expiry: FiniteDuration,
    val maxIdle: Option[FiniteDuration]
) extends EncryptedCookieAuthenticator[F, I, V, A] {
  def withKey(newKey: SecretKey[A]): StatelessECAuthenticator[F, I, V, A]

  def withSettings(settings: TSecCookieSettings): StatelessECAuthenticator[F, I, V, A]

  def withIdentityStore(newStore: IdentityStore[F, I, V]): StatelessECAuthenticator[F, I, V, A]
}

/** An authenticated cookie implementation
  *
  * @param id the cookie id
  * @param content the raw cookie: The full thing, including the nonce
  * @param identity The id of what
  * @param expiry
  * @param lastTouched
  * @tparam A
  * @tparam Id
  */
final case class AuthEncryptedCookie[A, Id](
    id: UUID,
    name: String,
    content: AEADCookie[A],
    identity: Id,
    expiry: Instant,
    lastTouched: Option[Instant],
    secure: Boolean,
    httpOnly: Boolean = true,
    domain: Option[String] = None,
    path: Option[String] = None,
    sameSite: Option[SameSite] = SameSite.Lax.some,
    extension: Option[String] = None
) {

  def toCookie = ResponseCookie(
    name,
    content,
    Some(HttpDate.unsafeFromInstant(expiry)),
    None,
    domain,
    path,
    sameSite,
    secure,
    httpOnly,
    extension
  )
}

object AuthEncryptedCookie {

  implicit def auth[A, Id]: AuthToken[AuthEncryptedCookie[A, Id]] = new AuthToken[AuthEncryptedCookie[A, Id]] {
    def expiry(a: AuthEncryptedCookie[A, Id]): Instant = a.expiry

    def lastTouched(a: AuthEncryptedCookie[A, Id]): Option[Instant] = a.lastTouched
  }

  final case class Internal[Id](id: UUID, messageId: Id, expiry: Instant, lastTouched: Option[Instant])
  object Internal {
    implicit def encoder[Id: Encoder]: Encoder[Internal[Id]] = _root_.io.circe.generic.semiauto.deriveEncoder
  }

  def build[A, Id](
      id: UUID,
      content: AEADCookie[A],
      messageId: Id,
      expiry: Instant,
      lastTouched: Option[Instant],
      settings: TSecCookieSettings
  ): AuthEncryptedCookie[A, Id] =
    AuthEncryptedCookie[A, Id](
      id,
      settings.cookieName,
      content,
      messageId,
      expiry,
      lastTouched,
      settings.secure,
      settings.httpOnly,
      settings.domain,
      settings.path,
      settings.sameSite,
      settings.extension
    )

  def build[A, Id](
      internal: Internal[Id],
      content: AEADCookie[A],
      settings: TSecCookieSettings
  ): AuthEncryptedCookie[A, Id] =
    AuthEncryptedCookie[A, Id](
      internal.id,
      settings.cookieName,
      content,
      internal.messageId,
      internal.expiry,
      internal.lastTouched,
      settings.secure,
      settings.httpOnly,
      settings.domain,
      settings.path,
      settings.sameSite,
      settings.extension
    )

}

object EncryptedCookieAuthenticator {

  private[tsec] def isExpired[I, A](
      internal: AuthEncryptedCookie[A, I],
      now: Instant,
      maxIdle: Option[FiniteDuration]
  ): Boolean =
    !internal.isExpired(now) && !maxIdle.exists(internal.isTimedOut(now, _))

  /** The default Encrypted cookie Authenticator, with a backing store.
    *
    * @param settings the cookie settings
    * @param tokenStore the token backing store
    * @param identityStore the backing store of the identity
    * @param key the symmetric signing key
    * @tparam F the effect type
    * @tparam A the symmetric key algorithm to use authenticated encryption
    * @tparam I the id type for a user
    * @tparam V the expected user type, V aka value
    * @return An encrypted cookie authenticator
    */
  def withBackingStore[F[_], I, V, A: AES](
      settings: TSecCookieSettings,
      tokenStore: BackingStore[F, UUID, AuthEncryptedCookie[A, I]],
      identityStore: IdentityStore[F, I, V],
      key: SecretKey[A]
  )(
      implicit F: Sync[F],
      instance: JAuthEncryptor[F, A],
      ivStrat: IvGen[F, A]
  ): StatefulECAuthenticator[F, I, V, A] =
    new StatefulECAuthenticator[F, I, V, A](settings.expiryDuration, settings.maxIdle) {

      /** Return a new instance with a modified key */
      def withKey(newKey: SecretKey[A]): StatefulECAuthenticator[F, I, V, A] =
        withBackingStore(
          settings,
          tokenStore,
          identityStore,
          newKey
        )

      /** Return a new instance with modified settings */
      def withSettings(settings: TSecCookieSettings): StatefulECAuthenticator[F, I, V, A] =
        withBackingStore(
          settings,
          tokenStore,
          identityStore,
          key
        )

      /** Return a new instance with a different identity store */
      def withIdentityStore(newStore: IdentityStore[F, I, V]): StatefulECAuthenticator[F, I, V, A] =
        withBackingStore(
          settings,
          tokenStore,
          newStore,
          key
        )

      /** Return a new instance with a different token store */
      def withTokenStore(
          newStore: BackingStore[F, UUID, AuthEncryptedCookie[A, I]]
      ): StatefulECAuthenticator[F, I, V, A] =
        withBackingStore(
          settings,
          newStore,
          identityStore,
          key
        )

      /** Generate our AAD: A sort of nonce to use for authentication with our encryption
        *
        */
      private def generateAAD(message: String) =
        AAD(SHA1.hashPure((message + Instant.now.toEpochMilli).utf8Bytes))

      /** Validate the cookie against the raw representation, and
        * validate against possibly expiration or timeout
        *
        */
      private def validateCookie(
          internal: AuthEncryptedCookie[A, I],
          raw: AEADCookie[A],
          now: Instant
      ): Boolean =
        internal.content === raw && isExpired[I, A](internal, now, settings.maxIdle)

      /** lift the validation onto an optionT
        *
        */
      private def validateAndRefresh(
          internal: AuthEncryptedCookie[A, I],
          raw: AEADCookie[A],
          now: Instant
      ): F[AuthEncryptedCookie[A, I]] =
        if (validateCookie(internal, raw, now)) refresh(internal) else F.raiseError(AuthenticationFailure)

      def extractRawOption(request: Request[F]): Option[String] =
        unliftedCookieFromRequest(settings.cookieName, request).map(_.content)

      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AuthEncryptedCookie[A, I]]] =
        OptionT(
          (for {
            now <- F.delay(Instant.now())
            coerced = AEADCookie[A](raw)
            contentRaw <- AEADCookieEncryptor.retrieveFromSigned[F, A](coerced, key)
            tokenId    <- uuidFromRaw[F](contentRaw)
            authed     <- tokenStore.get(tokenId).orAuthFailure
            refreshed  <- validateAndRefresh(authed, coerced, now)
            identity   <- identityStore.get(authed.identity).orAuthFailure
          } yield SecuredRequest(request, identity, refreshed).some)
            .handleError(_ => None)
        )

      /** Create a new cookie from the id field of a particular user.
        *
        */
      def create(body: I): F[AuthEncryptedCookie[A, I]] =
        for {
          cookieId <- F.delay(UUID.randomUUID())
          now      <- F.delay(Instant.now())
          expiry      = now.plusSeconds(settings.expiryDuration.toSeconds)
          lastTouched = settings.maxIdle.map(_ => now)
          messageBody = cookieId.toString
          encrypted <- AEADCookieEncryptor.signAndEncrypt[F, A](messageBody, generateAAD(messageBody), key)
          cookie    <- F.pure(AuthEncryptedCookie.build[A, I](cookieId, encrypted, body, expiry, lastTouched, settings))
          _         <- tokenStore.put(cookie)
        } yield cookie

      /** Update our authenticator in the backing store.
        *
        */
      def update(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] =
        tokenStore.update(authenticator)

      /** Discard our authenticator from the backing store
        *
        */
      def discard(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] =
        tokenStore.delete(authenticator.id).map(_ => authenticator.copy(expiry = Instant.EPOCH))

      /** Renew, aka reset both the expiry as well as the last touched (if present) value
        *
        */
      def renew(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] =
        F.delay(Instant.now()).flatMap { now =>
          settings.maxIdle match {
            case Some(_) =>
              val updated = authenticator.copy[A, I](
                lastTouched = Some(now),
                expiry = now.plusSeconds(settings.expiryDuration.toSeconds)
              )
              tokenStore.update(updated).map(_ => updated)
            case None =>
              val updated = authenticator.copy[A, I](
                expiry = now.plusSeconds(settings.expiryDuration.toSeconds)
              )
              tokenStore.update(updated).map(_ => updated)
          }
        }

      /** Touch our authenticator. Only used for sliding window expiration. Otherwise, it will be a no-op.
        *
        */
      def refresh(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] =
        settings.maxIdle match {
          case Some(_) =>
            F.delay(Instant.now())
              .flatMap(
                now =>
                  tokenStore.update(
                    authenticator.copy[A, I](
                      lastTouched = Some(now)
                    )
                )
              )
          case None =>
            F.pure(authenticator)
        }

      def embed(response: Response[F], authenticator: AuthEncryptedCookie[A, I]): Response[F] =
        response.addCookie(authenticator.toCookie)

      def afterBlock(response: Response[F], authenticator: AuthEncryptedCookie[A, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](response.addCookie(authenticator.toCookie))
          case None =>
            OptionT.pure[F](response)
        }
    }

  /**
    * Generate a stateless cookie authenticator that stores the authentication data, but not a token, in a backing store.
    * Since we have no way to verify that the cookie's expiration and sliding window haven't been modified,
    * we encrypt it as part of the contents
    *
    */
  def stateless[F[_], I: Decoder: Encoder, V, A: AES](
      settings: TSecCookieSettings,
      identityStore: IdentityStore[F, I, V],
      key: SecretKey[A]
  )(
      implicit F: Sync[F],
      instance: JAuthEncryptor[F, A],
      ivStrat: IvGen[F, A]
  ): StatelessECAuthenticator[F, I, V, A] =
    new StatelessECAuthenticator[F, I, V, A](settings.expiryDuration, settings.maxIdle) {

      def withKey(newKey: SecretKey[A]): StatelessECAuthenticator[F, I, V, A] =
        stateless[F, I, V, A](
          settings,
          identityStore,
          newKey
        )

      def withSettings(settings: TSecCookieSettings): StatelessECAuthenticator[F, I, V, A] =
        stateless[F, I, V, A](
          settings,
          identityStore,
          key
        )

      def withIdentityStore(newStore: IdentityStore[F, I, V]): StatelessECAuthenticator[F, I, V, A] =
        stateless[F, I, V, A](
          settings,
          newStore,
          key
        )

      private def generateAAD(message: String) =
        AAD(SHA1.hashPure((message + Instant.now.toEpochMilli).utf8Bytes))

      /** Inside a stateless cookie, we do not have a backing store, thus checking with the AuthEncryptedCookie is
        * useless
        *
        */
      private def validateAndRefresh(
          internal: AuthEncryptedCookie[A, I],
          now: Instant
      ): OptionT[F, AuthEncryptedCookie[A, I]] =
        if (isExpired(internal, now, settings.maxIdle)) OptionT.liftF(refresh(internal)) else OptionT.none

      def extractRawOption(request: Request[F]): Option[String] =
        unliftedCookieFromRequest(settings.cookieName, request).map(_.content)

      /** Unfortunately, parseRaw is not enough **/
      def parseRaw(raw: String, request: Request[F]): OptionT[F, SecuredRequest[F, V, AuthEncryptedCookie[A, I]]] =
        (for {
          now       <- OptionT.liftF(F.delay(Instant.now()))
          rawCookie <- cookieFromRequest[F](settings.cookieName, request)
          coerced = AEADCookie[A](rawCookie.content)
          contentRaw <- OptionT.liftF(AEADCookieEncryptor.retrieveFromSigned[F, A](coerced, key))
          internal   <- OptionT.liftF(F.fromEither(decode[AuthEncryptedCookie.Internal[I]](contentRaw)))
          authed = AuthEncryptedCookie.build[A, I](internal, coerced, settings)
          refreshed <- validateAndRefresh(authed, now)
          identity  <- identityStore.get(authed.identity)
        } yield SecuredRequest(request, identity, refreshed))
          .handleErrorWith(_ => OptionT.none)

      /** Create our cookie
        * In the case of encrypted cookies, we cannot trust the client to avoid tampering.
        * Thus, we unfortunately have to encrypt the expiry data as well
        *
        */
      def create(body: I): F[AuthEncryptedCookie[A, I]] =
        for {
          cookieId <- F.delay(UUID.randomUUID())
          now      <- F.delay(Instant.now())
          expiry      = now.plusSeconds(settings.expiryDuration.toSeconds)
          lastTouched = settings.maxIdle.map(_ => now)
          messageBody = AuthEncryptedCookie.Internal(cookieId, body, expiry, lastTouched).asJson.printWith(JWTPrinter)
          encrypted <- AEADCookieEncryptor.signAndEncrypt[F, A](messageBody, generateAAD(messageBody), key)
        } yield AuthEncryptedCookie.build[A, I](cookieId, encrypted, body, expiry, lastTouched, settings)

      /** Reader's note:
        * Since this is a stateless authenticator, update must carry information about expiry and sliding window info
        * since this is something that could be manipulated by an attacker.
        *
        * We sincerely don't want this, thus renew and refresh also rely on update.
        * */
      def update(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] = {
        val serialized = AuthEncryptedCookie
          .Internal(authenticator.id, authenticator.identity, authenticator.expiry, authenticator.lastTouched)
          .asJson
          .printWith(JWTPrinter)
        for {
          encrypted <- AEADCookieEncryptor.signAndEncrypt[F, A](serialized, generateAAD(serialized), key)
        } yield authenticator.copy[A, I](content = encrypted)
      }

      /** In this case, since we have no backing store, we can invalidate the token.
        * This doesn't work entirely if the person _doesn't_ set the token afterwards.
        *
        * @param authenticator
        * @return
        */
      def discard(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] =
        F.delay(authenticator.copy[A, I](content = AEADCookie[A]("invalid"), expiry = Instant.EPOCH))

      /** Renew all of our cookie's possible expirations.
        * If there is a timeout, refresh that as well. otherwise, simply update the expiry.
        *
        */
      def renew(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] =
        F.delay(Instant.now()).flatMap { now =>
          settings.maxIdle match {
            case Some(idleTime) =>
              update(
                authenticator.copy[A, I](
                  lastTouched = Some(now),
                  expiry = now.plusSeconds(settings.expiryDuration.toSeconds)
                )
              )
            case None =>
              update(
                authenticator.copy[A, I](
                  expiry = now.plusSeconds(settings.expiryDuration.toSeconds)
                )
              )
          }
        }

      def refresh(authenticator: AuthEncryptedCookie[A, I]): F[AuthEncryptedCookie[A, I]] =
        settings.maxIdle match {
          case Some(_) =>
            F.delay(
                authenticator.copy[A, I](
                  lastTouched = Some(Instant.now())
                )
              )
              .flatMap(update)
          case None =>
            F.pure(authenticator)
        }

      def embed(response: Response[F], authenticator: AuthEncryptedCookie[A, I]): Response[F] =
        response.addCookie(authenticator.toCookie)

      def afterBlock(response: Response[F], authenticator: AuthEncryptedCookie[A, I]): OptionT[F, Response[F]] =
        settings.maxIdle match {
          case Some(_) =>
            OptionT.pure[F](response.addCookie(authenticator.toCookie))
          case None =>
            OptionT.pure[F](response)
        }
    }
}
