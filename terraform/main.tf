provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "example_public_bucket" {
  bucket = "example-public-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_web_sg" {
  name        = "open-web-sg"
  description = "Allow public HTTP access"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "example_policy" {
  name   = "example-wildcard-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
