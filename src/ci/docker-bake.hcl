
variable "IMAGE_NAME" {
  default = "argentinaluiz/docker-prod-test"
}

target "docker-metadata-action" {}


group "default" {
    targets = [ "prod" ]
}

target "prod" {
    inherits = ["docker-metadata-action"]
    context = "./nestjs-project"
    dockerfile = "./Dockerfile.prod"
    secret = [ 
    {
      type = "env"
      id = "github_token"
    }
  ]
}

target "ci"  {
  context = "./nestjs-project"
  dockerfile = "./Dockerfile.prod"
  tags = [ "${IMAGE_NAME}:ci" ]
  target = "ci"
  secret = [ 
    {
      type = "env"
      id = "github_token"
    }
  ]
}