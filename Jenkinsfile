import com.cloudbees.ops.Builder
import com.cloudbees.ops.aws.*

node {
  def builder = new Builder()
  builder.scmUrl      = 'ssh://git@github.com/cloudbees/amazon-ecs-agent.git'
  builder.dockerImage = "amazon/amazon-ecs-agent"
  builder.orchestrate()
}
