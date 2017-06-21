import com.cloudbees.ops.aws.*;

node {
  def repo = "538462253088.dkr.ecr.us-east-1.amazonaws.com"
  def image = "amazon/amazon-ecs-agent"
  def image_tag = "build-${env.BUILD_NUMBER}"

  stage("Checkout") {
    git url: "ssh://git@github.com/cloudbees/amazon-ecs-agent", branch: 'vault'
  }

  stage("Build") {
    sh """
make
docker tag ${image}:make ${repo}/${image}:${image_tag}
"""
  }

  stage("Push") {
      (new ECR()).login()
      sh """
        docker push ${repo}/${image}:${image_tag}
      """
  }
}
