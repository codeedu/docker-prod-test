group "default" {
    targets = ["golang-app-prod"]
}

target "golang-app-prod" {
    context = "."
    dockerfile = "Dockerfile"
    tags = ["golang-app:latest"]
}

target "golang-app-ci" {
    context = "."
    dockerfile = "Dockerfile"
    tags = ["golang-app:ci"]
    target = "builder"
}