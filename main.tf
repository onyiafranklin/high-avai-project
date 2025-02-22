locals {
   name    = "team2"
  email   = "bolatito05@gmail.com"
  db-cred = jsondecode(aws_secretsmanager_secret_version.db_cred_version.secret_string)
}

resource "null_resource" "pre_scan" {
  provisioner "local-exec" {
    command = "./checkov_scan.sh"

    interpreter = ["bash", "-c"]
  }

  provisioner "local-exec" {
    when    = destroy
    command = "rm -f checkov_output.JSON"
  }

  triggers = {
    always_run = "${timestamp()}"

  }
}

output "pre_scan_status" {
  value = "Pre-scan completed. Check Slack and checkov_output.JSON file for details."
}

resource "aws_vpc" "vpc" {
  cidr_block       = var.cidr
  instance_tenancy = "default"

  tags = {
    Name = "${local.name}-vpc"
  }
}

# create public subnet 1
resource "aws_subnet" "pub_sub1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.public_subnet_1
  availability_zone = "eu-west-3a"

  tags = {
    Name = "${local.name}-pub_sub1"
  }
}

# create public subnet 2
resource "aws_subnet" "pub_sub2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.public_subnet_2
  availability_zone = "eu-west-3b"

  tags = {
    Name = "${local.name}-pub_sub2"
  }
}

# create private subnet 1
resource "aws_subnet" "pri_sub1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.private_subnet_1
  availability_zone = "eu-west-3a"

  tags = {
    Name = "${local.name}-pri_sub1"
  }
}

# create private subnet 2
resource "aws_subnet" "pri_sub2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.private_subnet_2
  availability_zone = "eu-west-3b"

  tags = {
    Name = "${local.name}-pri_sub2"
  }
}

# create internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
  }
}

# create nat gateway
resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.pub_sub1.id

  tags = {
    Name = "${local.name}-ngw"
  }
}

# create elastic ip
resource "aws_eip" "eip" {
  domain = "vpc"

  tags = {
    Name = "${local.name}-eip"
  }
}

# Create route tabble for public subnets
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.all-cidr
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "${local.name}-pub_rt"
  }
}

# Create route table for private subnets
resource "aws_route_table" "pri_rt" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.all-cidr
    gateway_id = aws_nat_gateway.ngw.id
  }
  tags = {
    Name = "${local.name}-pri_rt"
  }
}

# Creating route table association for public_subnet_1
resource "aws_route_table_association" "ass-public_subnet_1" {
  subnet_id      = aws_subnet.pub_sub1.id
  route_table_id = aws_route_table.pub_rt.id
}

# Creating route table association for public_subnet_2
resource "aws_route_table_association" "ass-public_subnet_2" {
  subnet_id      = aws_subnet.pub_sub2.id
  route_table_id = aws_route_table.pub_rt.id
}

# Creating route table association for private_subnet_1
resource "aws_route_table_association" "ass-private_subnet_1" {
  subnet_id      = aws_subnet.pri_sub1.id
  route_table_id = aws_route_table.pri_rt.id
}

# Creating route table association for private_subnet_2
resource "aws_route_table_association" "ass-private_subnet_2" {
  subnet_id      = aws_subnet.pri_sub2.id
  route_table_id = aws_route_table.pri_rt.id
}

# Frontend security group

resource "aws_security_group" "frontend-SG" {
  name        = "frontend-SG"
  description = "Allow inbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "HTTP"
    from_port   = var.httpport
    to_port     = var.httpport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS"
    from_port   = var.httpsport
    to_port     = var.httpsport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "SSH"
    from_port   = var.sshport
    to_port     = var.sshport
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name}-frontend-SG"
  }
}

#RDS security group
resource "aws_security_group" "RDS-SG" {
  name        = "RDS-SG"
  description = "Allow outbound traffic"
  vpc_id      = aws_vpc.vpc.id
  ingress {
    description = "MYSQPORT"
    from_port   = var.mysqlport
    to_port     = var.mysqlport
    protocol    = "tcp"
    cidr_blocks = ["${var.public_subnet_1}", "${var.public_subnet_2}"]
  }
  egress {
    description = "All TRAFFIC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "${local.name}-RDS-SG"
  }
}

#creating the secret manager
resource "aws_secretsmanager_secret" "db_cred2" {
  name                    = "db-cred2"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_cred_version" {
  secret_id     = aws_secretsmanager_secret.db_cred2.id
  secret_string = jsonencode(var.dbcred2)
}

# create media bucktet
resource "aws_s3_bucket" "team2_media" {
  bucket        = "team2-media"
  force_destroy = true
  depends_on    = [null_resource.pre_scan]
  tags = {
    Name = "${local.name}-media"
  }

}

resource "aws_s3_bucket_public_access_block" "team2_media_pub" {
  bucket                  = aws_s3_bucket.team2_media.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false

}

resource "aws_s3_bucket_ownership_controls" "team2_media_ctrl" {
  bucket = aws_s3_bucket.team2_media.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
  depends_on = [aws_s3_bucket_public_access_block.team2_media_pub]

}

# Media Bucket policy
resource "aws_s3_bucket_policy" "team2_media_policy" {
  bucket = aws_s3_bucket.team2_media.id
  policy = data.aws_iam_policy_document.team2_media_policy.json
}

data "aws_iam_policy_document" "team2_media_policy" {

  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetObjectVersion"
    ]
    resources = [
      aws_s3_bucket.team2_media.arn,
      "${aws_s3_bucket.team2_media.arn}/*",
    ]
  }
}

# S3 code Bucket 
resource "aws_s3_bucket" "team2_code_bucket" {
  bucket        = "team2-code-bucket"
  depends_on    = [null_resource.pre_scan]
  force_destroy = true

  tags = {
    Name = "${local.name}-code_bucket"
  }
}

# creating IAM role
resource "aws_iam_role" "iam_role1" {
  name = "${local.name}-iam_role1"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "iam_role"
  }
}

# creating media bucket iam policy
resource "aws_iam_policy" "team2-s3-policy" {
  name = "team2-s3-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:*"]
        Resource = "*"
        Effect   = "Allow"
      },
    ]
  })
}
resource "aws_iam_role_policy_attachment" "iam_s3_attachment" {
  role       = aws_iam_role.iam_role1.name
  policy_arn = aws_iam_policy.team2-s3-policy.arn
}

#creating iam instance profile
resource "aws_iam_instance_profile" "iam-instance-profile1" {
  name = "${local.name}-instance-profile1"
  role = aws_iam_role.iam_role1.name
}

#creating log bucket
resource "aws_s3_bucket" "team2-log-bucket" {
  bucket        = "team2-log-bucket"
  depends_on    = [null_resource.pre_scan]
  force_destroy = true
  tags = {
    Name = "${local.name}-log-bucket"
  }
}

#creating log bucket acl
resource "aws_s3_bucket_acl" "log_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.log_bucket_owner]
  bucket     = aws_s3_bucket.team2-log-bucket.id
  acl        = "private"
}
resource "aws_s3_bucket_ownership_controls" "log_bucket_owner" {
  bucket = aws_s3_bucket.team2-log-bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

#creating log bucket policy
data "aws_iam_policy_document" "log-bucket-access-policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
      "s3:GetBucketAcl",
      "s3:PutBucketAcl",
      "s3:PutObject"
    ]

    resources = [
      aws_s3_bucket.team2-log-bucket.arn,
      "${aws_s3_bucket.team2-log-bucket.arn}/*",
    ]
  }
}

resource "aws_s3_bucket_policy" "team2-log-bucket-policy" {
  bucket = aws_s3_bucket.team2-log-bucket.id
  policy = data.aws_iam_policy_document.log-bucket-access-policy.json
}

resource "aws_s3_bucket_public_access_block" "log_bucket_access_block" {
  bucket = aws_s3_bucket.team2-log-bucket.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}



#creating ACM certificate
resource "aws_acm_certificate" "acm-cert" {
  domain_name       = "selfdevops.space"
  validation_method = "DNS"

  tags = {
    Name = "${local.name}-acm-cert"
  }
}
#creating keypair RSA key of size 4096 bits
resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# creating private key
resource "local_file" "key" {
  content         = tls_private_key.key.private_key_pem
  filename        = "team2-key"
  file_permission = "600"
  depends_on      = [null_resource.pre_scan]
}

# creating public key
resource "aws_key_pair" "key-pub" {
  key_name   = "team2-pub-key1"
  public_key = tls_private_key.key.public_key_openssh
}

# Creating Instance
resource "aws_instance" "wordpress_server" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  depends_on                  = [null_resource.pre_scan]
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.frontend-SG.id, aws_security_group.RDS-SG.id]
  subnet_id                   = aws_subnet.pub_sub1.id
  iam_instance_profile        = aws_iam_instance_profile.iam-instance-profile1.id
  key_name                    = aws_key_pair.key-pub.id
  user_data                   = local.wordpress_script
  tags = {
    Name = "${local.name}-wordpress_server"
  }
}

# creating DB subnet 
resource "aws_db_subnet_group" "team2-database" {
  name       = "team2-database"
  subnet_ids = [aws_subnet.pri_sub1.id, aws_subnet.pri_sub2.id]

  tags = {
    Name = "${local.name}-DB-subnet"
  }
}
# creating RDS
resource "aws_db_instance" "wordpress-db-team2" {
  identifier             = var.db-identifier
  db_subnet_group_name   = aws_db_subnet_group.team2-database.name
  vpc_security_group_ids = [aws_security_group.RDS-SG.id]
  allocated_storage      = 10
  db_name                = var.dbname
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  username               = local.db-cred.username
  password               = local.db-cred.password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_type           = "gp2"
}
resource "aws_ami_from_instance" "team2-asg-ami" {
  name                    = "team2-asg-ami"
  source_instance_id      = aws_instance.wordpress_server.id
  snapshot_without_reboot = true
  depends_on              = [aws_instance.wordpress_server, time_sleep.ami-sleep]

}

resource "time_sleep" "ami-sleep" {
  depends_on      = [aws_instance.wordpress_server]
  create_duration = "420s"

}
# Creating Launch Template
resource "aws_launch_template" "lnch_tmpl" {
  name_prefix   = "${local.name}-web_tmpl"
  image_id      = aws_ami_from_instance.team2-asg-ami.id
  instance_type = var.instance_type
  key_name = aws_key_pair.key-pub.id
  iam_instance_profile {
    name = aws_iam_instance_profile.iam-instance-profile1.id
  }
  network_interfaces {
    associate_public_ip_address = true
    security_groups = [aws_security_group.frontend-SG.id]
  }
  user_data = base64encode(local.wordpress_script)
}
# Creating Auto Scaling Group with Launch Template
resource "aws_autoscaling_group" "autoscaling_grp" {
  name                      = "${local.name}-asg"
  max_size                  = 5
  min_size                  = 1
  desired_capacity          = 2
  health_check_grace_period = 300
  health_check_type         = "EC2"
  force_delete              = true

  # Corrected launch template reference
  launch_template {
    id      = aws_launch_template.lnch_tmpl.id
    version = "$Latest"
  }
  vpc_zone_identifier = [aws_subnet.pub_sub1.id, aws_subnet.pub_sub2.id]
  target_group_arns   = [aws_lb_target_group.TG.arn]
  tag {
    key                 = "Name"
    value               = "ASG"
    propagate_at_launch = true
  }
}

# creating autoscaling policy
resource "aws_autoscaling_policy" "autoscaling_grp-policy" {
  autoscaling_group_name = aws_autoscaling_group.autoscaling_grp.name
  name                   = "$(local.name)-asg-policy"
  adjustment_type        = "ChangeInCapacity"
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }

    target_value = 50.0
  }
}

# creating target group
resource "aws_lb_target_group" "TG" {
  name     = "team2-TG"
  port     = var.httpport
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    interval            = 60
    port                = 80
    timeout             = 30
    path                = "/indextest.html"
    protocol            = "HTTP"
  }
}

# creating target group listener
resource "aws_lb_target_group_attachment" "TG-attach" {
  target_group_arn = aws_lb_target_group.TG.arn
  target_id        = aws_instance.wordpress_server.id
  port             = var.httpport
}

# creating load balancer
resource "aws_lb" "LB" {
  name                       = "team2-LB"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.frontend-SG.id]
  subnets                    = [aws_subnet.pub_sub1.id, aws_subnet.pub_sub2.id]
  enable_deletion_protection = false
  access_logs {
    bucket  = aws_s3_bucket.team2-log-bucket.id
    prefix  = "team2-LB-LOG"
    enabled = true
  }
  tags = {
    Name = "${local.name}-LB"
  }
}

# creating load balancer listener
resource "aws_lb_listener" "LB-listener" {
  load_balancer_arn = aws_lb.LB.arn
  port              = var.httpport
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.TG.arn
  }
}


locals {
  s3_origin_id = aws_s3_bucket.team2_media.id
}

#creating aws_cloudfront_distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.team2_media.bucket_domain_name
    origin_id   = local.s3_origin_id
  }

  enabled = true

  # Optional logging configuration for CloudFront access logs
  logging_config {
    include_cookies = false
    bucket          = "team2-log-bucket.s3.amazonaws.com"
    prefix          = "cloudfront-log"
  }

  # Default cache behavior configuration for serving images
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false  # Disable query string forwarding as images don't need them
      cookies {
        forward = "none"   # No need to forward cookies for serving static images
      }
    }

    viewer_protocol_policy = "allow-all"  # Allow requests to HTTPS and HTTP
    min_ttl                = 3600                 # Minimum TTL (1 hour) for caching
    default_ttl            = 86400                # Default TTL (1 day) for caching
    max_ttl                = 31536000             # Maximum TTL (1 year) for caching
  }

  # Using the most cost-effective CloudFront price class
  price_class = "PriceClass_100"

  # Restrictions (no geo restrictions applied)
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # Dependency to ensure scanning is completed before distribution
  depends_on = [null_resource.pre_scan]

  # Tagging for identification
  tags = {
    Name = "${local.name}-cloudfront"
  }

  # Default CloudFront SSL certificate (you can configure a custom certificate if needed)
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Data block to retrieve the CloudFront distribution information
data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.s3_distribution.id
}

# Route53 Hosted Zone
data "aws_route53_zone" "team2-zone" {
  name         = var.domain
  private_zone = false
}

#creating A record
resource "aws_route53_record" "team2-record1" {
  zone_id = data.aws_route53_zone.team2-zone.zone_id
  name    = var.domain
  type    = "A"
  alias {
    name                   = aws_lb.LB.dns_name
    zone_id                = aws_lb.LB.zone_id
    evaluate_target_health = true
  }
}

#creating cloudwatch dashboard
resource "aws_cloudwatch_dashboard" "EC2_cloudwatch_dashboard" {
  dashboard_name = "EC2dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", "${aws_instance.wordpress_server.id}", { "label" : "Average CPU Utilization" }]
          ]
          period  = 300
          region  = "eu-west-3"
          stacked = false
          stat    = "Average"
          title   = "EC2 Average CPUUtilization"
          view    = "timeSeries"
          yAxis = {
            left = {
              label     = "Percentage"
              showUnits = true
            }
          }
        }
      }
    ]
  })
}
resource "aws_cloudwatch_dashboard" "asg_cpu_utilization_dashboard" {
  dashboard_name = "asgcpuutilizationdashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "${aws_autoscaling_group.autoscaling_grp.id}", { "label" : "Average CPU Utilization" }]
          ]
          period  = 300
          view    = "timeSeries"
          stat    = "Average"
          stacked = false
          region  = "eu-west-3"
          title   = "Average CPU Utilization"
          yAxis = {
            left = {
              label     = "Percentage"
              showUnits = true
            }
          }
        }
      },
    ]
  })
}

# Creating cloudwatch metric alarm ec2 instance
resource "aws_cloudwatch_metric_alarm" "CMA_EC2_Instance" {
  alarm_name          = "CMA-Instance"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_sns_topic.server_alert.arn]
  dimensions = {
    InstanceId : aws_instance.wordpress_server.id
  }
}
# Creating cloudwatch metric alarm auto-scalling group
resource "aws_cloudwatch_metric_alarm" "CMA_Autoscaling_Group" {
  alarm_name          = "CMA-asg"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "This metric monitors asg cpu utilization"
  alarm_actions       = [aws_autoscaling_policy.autoscaling_grp-policy.arn, aws_sns_topic.server_alert.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoscaling_grp.name
  }
}
# creating sns topic
resource "aws_sns_topic" "server_alert" {
  name            = "server-alert"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
}

#creating sns topic subscription
resource "aws_sns_topic_subscription" "team2_updates_sqs_target" {
  topic_arn = aws_sns_topic.server_alert.arn
  protocol  = "email"
  endpoint  = local.email
}
