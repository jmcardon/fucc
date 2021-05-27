import Dependencies._

lazy val contributors = Seq(
  "jmcardon"             -> "Jose Cardona",
  "rsoeldner"            -> "Robert Soeldner",
  "hrhino"               -> "Harrison Houghton",
  "aeons"                -> "Bjørn Madsen",
  "ChristopherDavenport" -> "Christopher Davenport"
)

lazy val releaseSettings = {
  import ReleaseTransformations._
  Seq(
    releaseCrossBuild := true,
    releaseProcess := Seq[ReleaseStep](
      checkSnapshotDependencies,
      inquireVersions,
      runClean,
      runTest,
      setReleaseVersion,
      commitReleaseVersion,
      tagRelease,
      // For non cross-build projects, use releaseStepCommand("publishSigned")
      releaseStepCommandAndRemaining("+publishSigned"),
      setNextVersion,
      commitNextVersion,
      releaseStepCommand("sonatypeReleaseAll"),
      pushChanges
    ),
    publishTo := {
      val nexus = "https://oss.sonatype.org/"
      if (isSnapshot.value)
        Some("snapshots" at nexus + "content/repositories/snapshots")
      else
        Some("releases" at nexus + "service/local/staging/deploy/maven2")
    },
    credentials ++= (
      for {
        username <- Option(System.getenv().get("SONATYPE_USERNAME"))
        password <- Option(System.getenv().get("SONATYPE_PASSWORD"))
      } yield
        Credentials(
          "Sonatype Nexus Repository Manager",
          "oss.sonatype.org",
          username,
          password
        )
    ).toSeq,
    Test / publishArtifact := false,
    releasePublishArtifactsAction := PgpKeys.publishSigned.value,
    scmInfo := Some(
      ScmInfo(
        url("https://github.com/jmcardon/tsec"),
        "git@github.com:jmcardon/tsec.git"
      )
    ),
    homepage := Some(url("https://github.com/jmcardon/tsec")),
    licenses += ("MIT", url("http://opensource.org/licenses/MIT")),
    publishMavenStyle := true,
    pomIncludeRepository := { _ =>
      false
    },
    pomExtra := {
      <developers>
        {for ((username, name) <- contributors) yield
        <developer>
          <id>{username}</id>
          <name>{name}</name>
          <url>http://github.com/{username}</url>
        </developer>
        }
      </developers>
    }
  )
}

lazy val micrositeSettings = Seq(
  micrositeName := "TSec",
  micrositeBaseUrl := "/tsec",
  micrositeDescription := "A Type-Safe General Cryptography Library on the JVM",
  micrositeAuthor := "Jose Cardona",
  micrositeHomepage := "https://jmcardon.github.io/tsec/",
  micrositeGithubOwner := "jmcardon",
  micrositeGithubRepo := "tsec",
  micrositeDocumentationUrl := "/tsec/docs/symmetric.html",
  micrositeGitterChannel := false,
  micrositeGithubToken := sys.env.get("GITHUB_TOKEN")
)

def scalacOptionsForVersion(scalaVersion: String): Seq[String] = {
  val defaultOpts = Seq(
    "-unchecked",
    "-feature",
    "-deprecation",
    "-encoding",
    "utf8",
    "-language:higherKinds",
    "-language:implicitConversions",
    "-language:postfixOps"
  )
  val versionOpts: Seq[String] = CrossVersion.partialVersion(scalaVersion) match {
    case Some((2, major)) if major < 13 => Seq(
      "-Ywarn-adapted-args",
      "-Ywarn-inaccessible",
      "-Ywarn-nullary-override",
      "-Ypartial-unification",
    )
    case _ => Seq()
  }
  defaultOpts ++ versionOpts
}

lazy val commonSettings = Seq(
  libraryDependencies ++= Seq(
    Libraries.cats,
    Libraries.scalaTest,
    Libraries.scalaTestPlus,
    Libraries.scalaCheck,
    Libraries.commonsCodec,
    Libraries.fs2IO
  ),
  ThisBuild / organization := "io.github.jmcardon",
  scalaVersion := crossScalaVersions.value.last,
  crossScalaVersions := Seq("2.12.13", "2.13.5", "3.0.0"),
  Test / fork := true,
  run / fork := true,
  // doc / scalacOptions ++= Seq(
  //     "-sourcepath", (LocalRootProject / baseDirectory).value.getAbsolutePath,
  //     "-doc-source-url", "https://github.com/jmcardon/tsec/blob/v" + version.value + "€{FILE_PATH}.scala"
  // ),
  Test / parallelExecution := false,

  libraryDependencies ++= {
    if (isDotty(scalaVersion.value)) Seq.empty
    else Seq(
      compilerPlugin("org.typelevel" % "kind-projector" % "0.13.0" cross CrossVersion.full),
      compilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1"),
    )
  },
  scalacOptions ++= {
    if (isDotty(scalaVersion.value)) Seq("-source:3.0-migration")
    else Seq()
  },
  Compile / doc / sources := {
    val old = (Compile / doc / sources).value
    if (isDotty(scalaVersion.value))
      Seq()
    else
      old
  },
  scalacOptions ++= scalacOptionsForVersion(scalaVersion.value)
)

lazy val passwordHasherLibs = libraryDependencies ++= Seq(
  Libraries.sCrypt
)

lazy val bouncyLib = libraryDependencies += Libraries.BC

lazy val jwtCommonLibs = libraryDependencies ++= Seq(
  Libraries.circeCore,
  Libraries.circeGeneric,
  // Libraries.circeGenericExtras,
  Libraries.circeParser
)

lazy val http4sDeps = libraryDependencies ++= Seq(
  Libraries.http4sdsl,
  Libraries.http4sServer,
  Libraries.http4sCirce
)

lazy val loggingLibs = libraryDependencies ++= Seq(
  Libraries.log4s
)

lazy val root = Project(id = "tsec", base = file("."))
  .aggregate(
    common,
    bouncyCastle,
    bouncyHash,
    bouncyCipher,
    messageDigests,
    cipherCore,
    jwtCore,
    symmetricCipher,
    mac,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers,
    http4s,
    // microsite,
    oauth2,
    // bench,
    // examples,
    // libsodium
  ).settings(commonSettings, publishSettings, releaseSettings, noPublishSettings)

lazy val common = Project(id = "tsec-common", base = file("common"))
  .settings(commonSettings)
  .settings(publishSettings)
  .settings(releaseSettings)

lazy val bouncyCastle = Project(id = "tsec-bouncy", base = file("bouncycastle"))
  .settings(commonSettings)
  .settings(bouncyLib)
  .settings(publishSettings)
  .settings(releaseSettings)

lazy val passwordHashers = Project(id = "tsec-password", base = file("password-hashers"))
  .settings(commonSettings)
  .settings(passwordHasherLibs)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .settings(releaseSettings)

lazy val cipherCore = Project(id = "tsec-cipher-core", base = file("cipher-core"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .settings(releaseSettings)

lazy val symmetricCipher = Project(id = "tsec-cipher-jca", base = file("cipher-symmetric"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)
  .settings(releaseSettings)

lazy val mac = Project(id = "tsec-mac", base = file("mac"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .settings(releaseSettings)

lazy val messageDigests = Project(id = "tsec-hash-jca", base = file("message-digests"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .settings(releaseSettings)

lazy val bouncyHash = Project(id = "tsec-hash-bouncy", base = file("hashing-bouncy"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(bouncyCastle)
  .settings(releaseSettings)

lazy val bouncyCipher = Project(id = "tsec-cipher-bouncy", base = file("cipher-bouncy"))
  .settings(commonSettings)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(bouncyCastle)
  .settings(releaseSettings)

lazy val signatures = Project(id = "tsec-signatures", base = file("signatures"))
  .settings(commonSettings)
  .settings(bouncyLib)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(bouncyCastle)
  .settings(releaseSettings)

lazy val jwtCore = Project(id = "tsec-jwt-core", base = file("jwt-core"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(publishSettings)
  .settings(releaseSettings)
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
  .settings(releaseSettings)

lazy val jwtSig = Project(id = "tsec-jwt-sig", base = file("jwt-sig"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(bouncyLib)
  .settings(publishSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(jwtCore)
  .dependsOn(signatures)
  .dependsOn(messageDigests)
  .dependsOn(bouncyCastle)
  .settings(releaseSettings)

lazy val bench = Project(id = "tsec-bench", base = file("bench"))
  .settings(commonSettings)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(cipherCore)
  .dependsOn(symmetricCipher)
  .dependsOn(libsodium)
  .dependsOn(bouncyCipher)
  .dependsOn(bouncyHash)
  .dependsOn(mac)
  .settings(noPublishSettings)
  .enablePlugins(JmhPlugin)

lazy val examples = Project(id = "tsec-examples", base = file("examples"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(bouncyLib)
  .settings(passwordHasherLibs)
  .settings(http4sDeps)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(
    symmetricCipher,
    mac,
    messageDigests,
    signatures,
    jwtMac,
    jwtSig,
    passwordHashers,
    // http4s,
    bouncyHash,
    bouncyCipher,
    libsodium
  )
  .settings(noPublishSettings)

lazy val oauth2 = Project(id = "tsec-oauth2", base = file("oauth2"))
  .settings(commonSettings)
  .dependsOn(common % "compile->compile;test->test")
  .settings(noPublishSettings)

lazy val http4s = Project(id = "tsec-http4s", base = file("tsec-http4s"))
  .settings(commonSettings)
  .settings(jwtCommonLibs)
  .settings(passwordHasherLibs)
  .settings(http4sDeps)
  .settings(publishSettings)
  .settings(loggingLibs)
  .dependsOn(common % "compile->compile;test->test")
  .dependsOn(
    symmetricCipher,
    mac,
    messageDigests,
    passwordHashers,
    jwtMac
  )
  .settings(releaseSettings)


lazy val libsodium = Project(id = "tsec-libsodium", base = file("tsec-libsodium"))
  .settings(commonSettings)
  .settings(
    libraryDependencies ++= Seq(
      Libraries.fs2IO
    )
  )
  .settings(loggingLibs)
  .dependsOn(common % "compile->compile;test->test")
  .settings(releaseSettings)
  .settings(publishSettings)
/*
lazy val microsite = Project(id = "microsite", base = file("docs"))
  .settings(commonSettings, noPublishSettings)
  .settings(micrositeSettings)
  .enablePlugins(MicrositesPlugin)
  .enablePlugins(TutPlugin)
  .dependsOn(
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
    http4s,
    examples
  )
*/

lazy val publishSettings = Seq(
  homepage := Some(url("https://github.com/jmcardon/tsec")),
  licenses := Seq("MIT" -> url("https://opensource.org/licenses/MIT")),
  scmInfo := Some(ScmInfo(url("https://github.com/jmcardon/tsec"), "scm:git:git@github.com:jmcardon/tsec.git")),
)

lazy val noPublishSettings = {
  Seq(
    publish / skip := true,
    publish := (()),
    publishLocal := (()),
    publishArtifact := false,
    publishTo := None
  )
}

def isDotty(string: String): Boolean = {
  VersionNumber(string)._1.exists(_ == 3L)
}
