package tsec.messagedigests.instances

case class SHA1(array: Array[Byte])

object SHA1 extends DeriveHashTag[SHA1]("SHA-1")
