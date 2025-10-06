
variable "IMAGE_NAME" {
  default = "argentinaluiz/docker-prod-test"
}

target "docker-metadata-action" {
}


group "default" {
    targets = [ "prod" ]
}

target "prod" {
    inherits = ["docker-metadata-action"]
    context = "./app"
    dockerfile = "./Dockerfile.prod"
    tags = [ "${IMAGE_NAME}:latest" ]
}

target "ci"  {
  context = "./app"
  dockerfile = "./Dockerfile.prod"
  tags = [ "${IMAGE_NAME}:ci" ]
  target = "ci"
}