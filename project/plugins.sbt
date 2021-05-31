logLevel := Level.Warn
addSbtPlugin("com.47deg"          % "sbt-microsites" % "0.7.16")
// addSbtPlugin("org.tpolecat"       % "tut-plugin"     % "0.6.13")
addSbtPlugin("com.typesafe.sbt"   % "sbt-ghpages"    % "0.6.3")
addSbtPlugin("pl.project13.scala" % "sbt-jmh"        % "0.3.7")
addSbtPlugin("com.timushev.sbt"   % "sbt-updates"    % "0.3.3")
addSbtPlugin("com.github.gseitz"  % "sbt-release"    % "1.0.12")
addSbtPlugin("com.github.sbt" % "sbt-pgp" % "2.1.2")
addSbtPlugin("org.xerial.sbt"     % "sbt-sonatype"   % "2.6")
addSbtPlugin("ch.epfl.scala" % "sbt-scalafix" % "0.9.29")


libraryDependencies ++= List(
  "com.geirsson" %% "scalafmt-core" % "1.3.0",
  "com.geirsson" %% "scalafmt-cli"  % "1.3.0"
)

Compile / unmanagedJars ++= tsec.build.SunShine.`tools.jar`.toSeq

Compile / sources ++= {
  if (tsec.build.SunShine.canWeUseToolsDotJar_?)
    file("project/boiler/gensodium.scala").getAbsoluteFile :: Nil
  else Nil
}
