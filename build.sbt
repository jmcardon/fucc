import Dependencies._

name := "tsec"

scalaVersion := "2.12.3"

lazy val scalacOpts = scalacOptions := Seq(
  "-unchecked",
  "-feature",
  "-deprecation",
  "-encoding",
  "utf8",
  "-Ywarn-adapted-args", // Warn if an argument list is modified to match the receiver.
  "-Ywarn-inaccessible", // Warn about inaccessible types in method signatures.
  "-Ywarn-nullary-override", // Warn when non-nullary overrides nullary, e.g. def foo() over def foo.
  "-Ypartial-unification",
  "-language:higherKinds",
  "-language:implicitConversions"
)

lazy val commonSettings = Seq(
  libraryDependencies ++= Seq(
    Libraries.cats,
    Libraries.catsEffect,
    Libraries.scalaTest,
    Libraries.scalaCheck
  ),
  organization in ThisBuild := "io.github.jmcardon",
  scalaVersion in ThisBuild := "2.12.3",
  fork in test := true,
  parallelExecution in test := false,
  addCompilerPlugin("org.spire-math" %% "kind-projector" % "0.9.4"),
  version in ThisBuild := "0.0.1-M2",
  scalacOpts
)

lazy val benchSettings = Seq(
  resolvers += "Sonatype OSS Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots",
  libraryDependencies += Libraries.thyme
)

lazy val passwordHasherLibs = libraryDependencies ++= Seq(
  Libraries.sCrypt,
  Libraries.jBCrypt
)

lazy val signatureLibs = libraryDependencies += Libraries.BC

lazy val jwtCommonLibs = libraryDependencies ++= Seq(
  Libraries.circeCore,
  Libraries.circeGeneric,
  Libraries.circeGenericExtras,
  Libraries.circeParser
)

lazy val http4sDeps = libraryDependencies ++= Seq(
  Libraries.http4sdsl,
  Libraries.http4sServer,
  Libraries.http4sCirce
)

lazy val root = project
  .aggregate(
    common,
    messageDigests,
    cipherCore,
    jwtCore,
    symmetricCipher,
    mac,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers,
    http4s
  )

lazy val common = Project(id = "tsec-common", base = file("common"))
  .settings(commonSettings)
  .settings(publishSettings)

lazy val passwordHashers = Project(id = "tsec-password", base = file("password-hashers"))
  .settings(commonSettings)
  .settings(passwordHasherLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val cipherCore = Project(id = "tsec-cipher-core", base = file("cipher-core"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val symmetricCipher = Project(id = "tsec-symmetric-cipher", base = file("cipher-symmetric"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)

lazy val mac = Project(id = "tsec-mac", base = file("mac"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val messageDigests = Project(id = "tsec-md", base = file("message-digests"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val signatures = Project(id = "tsec-signatures", base = file("signatures"))
  .settings(commonSettings)
  .settings(signatureLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")

lazy val jwtCore = Project(id = "tsec-jwt-core", base = file("jwt-core"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(mac)
  .dependsOn(signatures)

lazy val jwtMac = Project(id = "tsec-jwt-mac", base = file("jwt-mac"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(mac)
  .dependsOn(jwtCore)

lazy val jwtSig = Project(id = "tsec-jwt-sig", base = file("jwt-sig"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(signatureLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(jwtCore)
  .dependsOn(signatures)
  .dependsOn(messageDigests)

lazy val bench = Project(id = "tsec-bench", base = file("bench"))
  .settings(commonSettings)
  .settings(benchSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)
  .dependsOn(symmetricCipher)
  .settings(publish := {})

lazy val examples = Project(id = "tsec-examples", base = file("examples"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(signatureLibs)
  .settings(passwordHasherLibs)
  .settings(http4sDeps)
  .dependsOn(
    symmetricCipher,
    mac,
    messageDigests,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers,
    http4s
  )
  .settings(publish := {})

lazy val http4s = Project(id = "tsec-http4s", base = file("tsec-http4s"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(passwordHasherLibs)
  .settings(http4sDeps)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(
    symmetricCipher,
    mac,
    messageDigests,
    jwtMac
  )

lazy val publishSettings = Seq(
  homepage := Some(url("https://github.com/jmcardon/tsec")),
  licenses := Seq("Apache-2.0" -> url("https://www.apache.org/licenses/LICENSE-2.0")),
  scmInfo := Some(ScmInfo(url("https://github.com/jmcardon/tsec"), "scm:git:git@github.com:jmcardon/tsec.git")),
  autoAPIMappings := true,
  apiURL := None,
  bintrayRepository := "tsec",
  pomExtra :=
    <developers>
    <developer>
      <id>jmcardon</id>
      <name>Jose Cardona</name>
      <url>https://github.com/jmcardon/</url>
    </developer>
    <developer>
      <id>rsoeldner</id>
      <name>Robert Soeldner</name>
      <url>https://github.com/rsoeldner/</url>
    </developer>
  </developers>
)
