package tsec.symmetric.instances

sealed trait AES192
object AES192 extends WithSymmetricGenerator[AES192]("AES_192", 192)
