import sbt._

object Dependencies {

  object Versions {
    val circeV        = "0.14.1"   //https://github.com/circe/circe/releases
    val catsV         = "2.6.1"        //https://github.com/typelevel/cats/releases
    val bouncyCastleV = "1.68"         //https://github.com/bcgit/bc-java/releases
    val sCryptV       = "1.4.0"        //https://github.com/wg/scrypt/releases
    val scalaTestV    = "3.2.9"      //https://github.com/scalatest/scalatest/releases
    val scalaTestPlusV= "3.2.9.0"  //https://github.com/scalatest/scalatestplus-scalacheck
    val http4sV       = "0.23.0-M1"   //https://github.com/http4s/http4s/releases
    val scalacheckV   = "1.15.4"       //https://github.com/typelevel/scalacheck/releases
    val commonsCodecV = "1.15"         //https://github.com/apache/commons-codec/releases
    val fs2Version    = "3.0.3"        //https://github.com/functional-streams-for-scala/fs2/releases
    val log4sV        = "1.9.0"        //https://github.com/Log4s/log4s
  }

  object Libraries {
    val fs2                = "co.fs2"            %% "fs2-core"        % Versions.fs2Version
    val fs2IO              = "co.fs2"            %% "fs2-io"          % Versions.fs2Version
    val cats               = "org.typelevel"     %% "cats-core"       % Versions.catsV
    val sCrypt             = "com.lambdaworks"   % "scrypt"           % Versions.sCryptV
    val scalaTest          = "org.scalatest"     %% "scalatest"       % Versions.scalaTestV % "test"
    val scalaTestPlus      = "org.scalatestplus" %% "scalacheck-1-15" % Versions.scalaTestPlusV % "test"
    val BC                 = "org.bouncycastle"  % "bcprov-jdk15on"   % Versions.bouncyCastleV
    val circeCore          = "io.circe"          %% "circe-core"      % Versions.circeV
    val circeGeneric       = "io.circe"          %% "circe-generic"   % Versions.circeV
    // val circeGenericExtras = "io.circe"         %% "circe-generic-extras" % Versions.circeV
    val circeParser        = "io.circe"       %% "circe-parser"  % Versions.circeV
    val http4sdsl          = "org.http4s"     %% "http4s-dsl"    % Versions.http4sV
    val http4sServer       = "org.http4s"     %% "http4s-server" % Versions.http4sV
    val http4sCirce        = "org.http4s"     %% "http4s-circe"  % Versions.http4sV % "test"
    val scalaCheck         = "org.scalacheck" %% "scalacheck"    % Versions.scalacheckV % "test"
    val commonsCodec       = "commons-codec"  % "commons-codec"  % Versions.commonsCodecV
    val log4s              = "org.log4s"      %% "log4s"         % Versions.log4sV
  }

}
