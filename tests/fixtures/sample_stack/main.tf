resource "aws_s3_bucket" "data" {
  bucket = "acme-prod-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "app" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.web.id]
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  username            = "admin"
  password            = "SuperSecretP@ssw0rd123"
}
