pluginManagement {
    repositories {
        maven { url = uri("https://example.invalid/plugins") }
        gradlePluginPortal()
    }
}
includeBuild("build-logic")
rootProject.name = "reviewed"
