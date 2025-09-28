group "default" {
    targets = [ "nestjs-prod" ]
}

target "nestjs-prod" {
    context = "./nestjs-project-insecure"
    dockerfile = "../Dockerfile"
    tags = ["nestjs:latest"]
}

target "nestjs-ci"  {
  context = "./nestjs-project-insecure"
  dockerfile = "../Dockerfile"
  tags = ["nestjs:ci"]
  target = "ci"
}