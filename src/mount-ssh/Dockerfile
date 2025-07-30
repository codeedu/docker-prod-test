FROM alpine

ARG REPO_PATH=git@github.com:argentinaluiz/private-repo.git

RUN apk add --no-cache git openssh-client

# clone repository
RUN --mount=type=ssh \
    #--mount=type=ssh,id=my_ssh
    mkdir -p /root/.ssh && \
    ssh-keyscan github.com >> /root/.ssh/known_hosts && \
    git clone $REPO_PATH /app

RUN chmod +x /app/script.sh

CMD ["/app/script.sh"]