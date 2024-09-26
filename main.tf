resource "aws_vpc" "myvpc" {
   cidr_block = var.cidr
}

resource "aws_subnet" "sub1" {
   vpc_id = aws_vpc.myvpc.id
   cidr_block = "10.0.0.0/24"
   availability_zone = "us-east-1a"
   map_public_ip_on_launch = true
}


resource "aws_subnet" "sub2" {
   vpc_id = aws_vpc.myvpc.id
   cidr_block = "10.0.1.0/24"
   availability_zone = "us-east-1b"
   map_public_ip_on_launch = true
}

resource "aws_internet_gateway" "igw" {
   vpc_id = aws_vpc.myvpc.id
}

resource "aws_route_table" "RT"{
   vpc_id = aws_vpc.myvpc.id
   
   route {
      cidr_block = "0.0.0.0/0"
      gateway_id = aws_internet_gateway.igw.id
   }
}

resource "aws_route_table_association" "rta1"{
   subnet_id = aws_subnet.sub1.id
   route_table_id = aws_route_table.RT.id
}

resource "aws_route_table_association" "rta2"{
   subnet_id = aws_subnet.sub2.id
   route_table_id = aws_route_table.RT.id
}

resource "aws_security_group" "allow_http_ssh" {
   name        = "allow_http_ssh"
   description = "Allow TLS inbound traffic and all outbound traffic"
   vpc_id      = aws_vpc.myvpc.id

   tags = {
    Name = "allow_http_ssh"
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_http_ipv4" {
   security_group_id = aws_security_group.allow_http_ssh.id
   cidr_ipv4         = aws_vpc.myvpc.cidr_block
   from_port         = 80
   ip_protocol       = "tcp"
   to_port           = 80
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh_ipv4" {
   security_group_id = aws_security_group.allow_http_ssh.id
   cidr_ipv4         = aws_vpc.myvpc.cidr_block
   from_port         = 22
   ip_protocol       = "tcp"
   to_port           = 22
}


resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
   security_group_id = aws_security_group.allow_http_ssh.id
   cidr_ipv4         = "0.0.0.0/0"
   ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_s3_bucket" "example" {
   bucket = "tarunsterraform2024project"
}

resource "aws_instance" "webserver1"{
   ami = "ami-0e86e20dae9224db8"
   instance_type = "t2.micro"
   vpc_security_group_ids = [aws_security_group.allow_http_ssh.id]
   subnet_id = aws_subnet.sub1.id
   user_data = base64encode(file("userdata.sh"))
   iam_instance_profile = aws_iam_instance_profile.ec2_s3_instance_profile_2.name 
}

resource "aws_instance" "webserver2"{
   ami = "ami-0e86e20dae9224db8"
   instance_type = "t2.micro"
   vpc_security_group_ids = [aws_security_group.allow_http_ssh.id]
   subnet_id = aws_subnet.sub2.id
   user_data = base64encode(file("userdata1.sh"))
   iam_instance_profile = aws_iam_instance_profile.ec2_s3_instance_profile.name

}

resource "aws_lb" "myalb" {
   name               = "myalb"
   internal           = false
   load_balancer_type = "application"
   security_groups    = [aws_security_group.allow_http_ssh.id]
   subnets            = [aws_subnet.sub1.id, aws_subnet.sub2.id]

   tags = {
    Name = "web"
  }
}

resource "aws_lb_target_group" "tg"{
   name        = "myTG"
   port        = 80
   protocol    = "HTTP"
   vpc_id      = aws_vpc.myvpc.id

   health_check {
    path = "/"
    port = "traffic-port"
  }

}

resource "aws_lb_target_group_attachment" "attach1" {
   target_group_arn = aws_lb_target_group.tg.arn
   target_id        = aws_instance.webserver1.id
   port             = 80
}

resource "aws_lb_target_group_attachment" "attach2" {
   target_group_arn = aws_lb_target_group.tg.arn
   target_id        = aws_instance.webserver2.id
   port             = 80
}

resource "aws_lb_listener" "listener" {
   load_balancer_arn = aws_lb.myalb.arn
   port = 80
   protocol = "HTTP"

   default_action {
    target_group_arn = aws_lb_target_group.tg.arn
    type = "forward"
  }
}

output "loadbalancerdns" {
   value = aws_lb.myalb.dns_name
}
###########################################################################
resource "aws_iam_role" "ec2_s3_access_role" {
   name = "ec2_s3_access_role"
################################################################################################   

   # the ec2 service is allowed to assume this role
   assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
       Action = "sts:AssumeRole"
       Effect = "Allow"
       Principal = {
        Service = "ec2.amazonaws.com"
      }
     },
    ]
  })
}



# Step 2: Attach a policy to the IAM Role that allows S3 access
resource "aws_iam_policy" "s3_access_policy" {
   name        = "S3_Access_Policy"
   description = "Policy to allow EC2 instances to access S3"
  
   policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]

        Effect   = "Allow"
        Resource = [
          "arn:aws:s3:::tarunsterraform2024project",  # Access to the S3 bucket
          "arn:aws:s3:::tarunsterraform2024project/*"  # Access to objects in the bucket
        ]
      }
    ]
  })
}

# Step 3: Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "s3_access_role_attach" {
   role       = aws_iam_role.ec2_s3_access_role.name
   policy_arn = aws_iam_policy.s3_access_policy.arn
}

# Step 5: Create an IAM instance profile to associate with EC2
resource "aws_iam_instance_profile" "ec2_s3_instance_profile" {
   name = "ec2_s3_instance_profile"
   role = aws_iam_role.ec2_s3_access_role.name
}

##########################################################################################################################

# Second the second IAM role for second ec2 instance 
resource "aws_iam_role" "ec2_s3_access_role_2" {
   name = "ec2_s3_access_role_2"


   # the ec2 service is allowed to assume this role
   assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
       Action = "sts:AssumeRole"
       Effect = "Allow"
       Principal = {
        Service = "ec2.amazonaws.com"
      }
     },
    ]
  })
}


# Step 2: Attach a policy to the IAM Role that allows S3 access
resource "aws_iam_policy" "s3_access_policy_2" {
   name        = "S3_Access_Policy_2"
   description = "Policy to allow EC2 instances to access S3"

   policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Effect   = "Allow"
        Resource = [
          "arn:aws:s3:::tarunsterraform2024project",  # Access to the S3 bucket
          "arn:aws:s3:::tarunsterraform2024project/*"  # Access to objects in the bucket
        ]
      }
    ]
  })
}

# Step 3: Attach the policy to the IAM role
resource "aws_iam_role_policy_attachment" "s3_access_role_2_attach" {
   role       = aws_iam_role.ec2_s3_access_role_2.name
   policy_arn = aws_iam_policy.s3_access_policy_2.arn
}

# Step 5: Create an IAM instance profile to associate with EC2
resource "aws_iam_instance_profile" "ec2_s3_instance_profile_2" {
   name = "ec2_s3_instance_profile_2"
   role = aws_iam_role.ec2_s3_access_role_2.name
}

