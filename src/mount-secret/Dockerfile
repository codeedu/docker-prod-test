FROM alpine

ARG REPO_PATH=github.com/argentinaluiz/private-repo

RUN apk add --no-cache git

# # usando variável de ambiente
# RUN --mount=type=secret,id=github_token,env=GITHUB_TOKEN \
#     git clone https://github_user:$GITHUB_TOKEN@$REPO_PATH /app

RUN --mount=type=secret,id=github_token \
    # --mount=type=secret,id=xpto1 \
    # --mount=type=secret,id=xpto2 \
    GITHUB_TOKEN=$(cat /run/secrets/github_token) && \
    git clone https://github_user:$GITHUB_TOKEN@$REPO_PATH /app

RUN echo "valor do env $GITHUB_TOKEN"

RUN chmod +x /app/script.sh

CMD ["/app/script.sh"]