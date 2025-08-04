group "default" {
    targets = [ "frontend", "backend-base", "backend" ]
}

target "frontend" {
    context = "./frontend"
    dockerfile = "Dockerfile"
    tags = ["namespace/frontend:latest"]
    platforms = ["linux/amd64", "linux/arm64"]
  //ssh = [ "value" ]
    cache-from = [
    {
      type = "registry"
      ref = "namespace/frontend:cache"
    }
  ]
    cache-to = [ 
    {
      type = "registry"
      ref = "namespace/frontend:cache"
      mode = "max"
    }
  ]
}

target "backend-base" {
  context = "./backend"
  dockerfile = "Dockerfile.base"
  tags = ["namespace/backend:base"]
  platforms = ["linux/amd64", "linux/arm64"]
  //ssh = [ "value" ]
  cache-from = [
    {
      type = "registry"
      ref = "namespace/app:base"
    }
  ]
  cache-to = [ 
    {
      type = "inline"
    }
  ]
}

target "backend" {
    contexts = {
      "namespace/backend:base" = "target:backend-base"
    }
    context = "./backend"
    dockerfile = "Dockerfile.prod"
    tags = ["namespace/backend:latest"]
    platforms = ["linux/amd64", "linux/arm64"]
    secret = [ 
    {
      id = "mysecret"
      src = "./mysecret.txt"
    }
  ]
  /*ssh = [ 
    {
      id = "default"
    } 
  ]*/
    cache-from = [
    {
      type = "registry"
      ref = "namespace/backend:cache"
    }
  ]
    cache-to = [ 
    {
      type = "registry"
      ref = "namespace/backend:cache"
      mode = "max"
    }
  ]  
}