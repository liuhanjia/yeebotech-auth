# 使用 Go 1.23.1 作为基础镜像
FROM golang:1.23.1 AS builder

# 设置工作目录
WORKDIR /app

# 将 go.mod 和 go.sum 复制到工作目录
COPY go.mod go.sum ./
RUN go mod download

# 将整个项目复制到工作目录
COPY . .

# 构建 Go 应用
RUN go build -o yeebotech-auth

# 使用轻量级的镜像
FROM alpine:latest

# 安装 libc6-compat 以支持 glibc 二进制文件
RUN apk add --no-cache libc6-compat

# 设置工作目录
WORKDIR /root/

# 从构建阶段复制构建好的二进制文件
COPY --from=builder /app/yeebotech-auth .

# 设置可执行权限
RUN chmod +x ./yeebotech-auth

# 复制 .env 文件
COPY .env ./

# 暴露端口
EXPOSE 8082

# 运行应用
CMD ["./yeebotech-auth"]
