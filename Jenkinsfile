pipeline {
  agent any

  environment {
    AWS_REGION     = 'ap-south-1'
    AWS_ACCOUNT_ID = '412917579743'
    ECR_REGISTRY   = "${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    // folders = repo dirs; ECR repo names should already exist with the same names
    SERVICES       = "classroom-service assignment-service submission-service materials-service"
    UI_PORT        = "5173"
  }

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('AWS ECR Login') {
      steps {
        // If you created AWS credentials in Jenkins (Option B), uncomment:
        // withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-jenkins']]) {
        sh '''
          set -e
          aws --version
          aws ecr get-login-password --region ${AWS_REGION} \
            | docker login --username AWS --password-stdin ${ECR_REGISTRY}
        '''
        // }
      }
    }

    stage('Build & Push Services') {
      steps {
        script {
          env.SHORT_SHA = sh(script: "git rev-parse --short HEAD", returnStdout: true).trim()
        }
        sh '''
          set -euo pipefail
          for SVC in ${SERVICES}; do
            echo "=== Building $SVC ==="
            IMG=${ECR_REGISTRY}/$SVC:${SHORT_SHA}
            docker build -t $IMG $SVC
            docker tag $IMG ${ECR_REGISTRY}/$SVC:latest
            docker push $IMG
            docker push ${ECR_REGISTRY}/$SVC:latest
          done
        '''
      }
    }

    stage('Build SPA') {
      steps {
        dir('classroom-spa') {
          sh '''
            set -e
            npm ci || npm install
            npm run build
          '''
        }
      }
    }

    stage('Run SPA (static server)') {
      steps {
        dir('classroom-spa') {
          sh '''
            set -e
            # stop previous instance if running
            if [ -f serve.pid ] && ps -p $(cat serve.pid) > /dev/null 2>&1; then
              kill $(cat serve.pid) || true
              sleep 1
            fi
            # start new
            nohup npx serve -s dist -l ${UI_PORT} > ../spa.log 2>&1 & echo $! > serve.pid
            echo "SPA listening on :${UI_PORT}"
          '''
        }
      }
    }
  }

  post {
    success {
      echo "Build OK. Images tagged :${SHORT_SHA} and :latest. SPA restarted."
    }
    failure {
      echo "Build failed. Check the stage logs."
    }
  }
}
